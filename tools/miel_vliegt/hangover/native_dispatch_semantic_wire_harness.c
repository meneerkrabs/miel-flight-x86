#include <stdio.h>

/* Test-only same-translation-unit access to the actual C emitters. */
#ifndef MVDS_PRODUCER_BUILD_SHA256
#define MVDS_PRODUCER_BUILD_SHA256 \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#endif
#define MVDS_TEST_MULTI_EMIT 1
#include "native_dispatch_semantic_hook.c"

static int g_emit_count;
static BOOL g_drop_capability;
static BOOL g_drop_event;

static BOOL harness_emit(const char *line, DWORD size, void *context) {
    (void)context;
    if ((g_drop_capability && g_emit_count == 0) ||
        (g_drop_event && g_emit_count == 1)) {
        g_emit_count++;
        return FALSE;
    }
    fwrite(line, 1, size, stdout);
    g_emit_count++;
    return TRUE;
}

static void harness_fail(const char *reason, void *context) {
    (void)context;
    fprintf(stderr, "FAIL %s\n", reason);
}

static BOOL harness_capture_complete(
    DWORD native_process_id, const char *capture_session_id, void *context
) {
    (void)context;
    return native_process_id == GetCurrentProcessId() &&
        capture_session_id != NULL && strncmp(capture_session_id,"mvds-",5) == 0;
}

static int run_hook_plan_contract(const char *mode) {
    size_t index;
    BOOL expected_success = strcmp(mode, "hook-plan-exact") == 0;
    for (index = 0; index < ARRAY_COUNT(g_specs); ++index) {
        *g_specs[index].trampoline_slot =
            mvds_hook_required(g_specs[index].id) ? (void *)(uintptr_t)1 : NULL;
    }
    if (strcmp(mode, "hook-plan-missing") == 0) {
        for (index = 0; index < ARRAY_COUNT(g_specs); ++index) {
            if (mvds_hook_required(g_specs[index].id)) {
                *g_specs[index].trampoline_slot = NULL;
                break;
            }
        }
    } else if (strcmp(mode, "hook-plan-extra") == 0) {
        for (index = 0; index < ARRAY_COUNT(g_specs); ++index) {
            if (!mvds_hook_required(g_specs[index].id)) {
                *g_specs[index].trampoline_slot = (void *)(uintptr_t)1;
                break;
            }
        }
    } else if (!expected_success) {
        return 11;
    }
    return mvds_arm(&g_host, FALSE) == expected_success ? 0 : 12;
}

static void *THISCALL harness_parse_noop(void *self, DWORD argument, const char *path) {
    (void)self; (void)argument; (void)path;
    return (void *)(uintptr_t)0x5678;
}

static void THISCALL harness_insert_noop(void *self, void *mission) {
    (void)self; (void)mission;
}

static void *THISCALL harness_parse_insert(void *self, DWORD argument, const char *path) {
    (void)argument; (void)path;
    hook_insert(self, 0, (void *)(uintptr_t)0x2000);
    return (void *)(uintptr_t)0x5678;
}

static int g_nested_parse_depth;

static void *THISCALL harness_parse_nested(void *self, DWORD argument, const char *path) {
    if (g_nested_parse_depth++ == 0)
        hook_parse(self, 0, argument, path);
    g_nested_parse_depth--;
    return (void *)(uintptr_t)0x5678;
}

static void *__cdecl harness_root_factory(void *owner, const char *path) {
    (void)owner; (void)path;
    SetLastError(0x1234);
    return (void *)(uintptr_t)0x4000;
}

static int run_negative(const char *name) {
    if (strcmp(name, "wrong-object") == 0) {
        begin_selector(SELECTOR_GENERIC, (void *)(uintptr_t)0x1000);
        mvds_observe_route(MVDS_ROUTE_GROUND, 0x2000, 0x3000);
    } else if (strcmp(name, "duplicate-route") == 0) {
        begin_selector(SELECTOR_GENERIC, (void *)(uintptr_t)0x1000);
        mvds_observe_route(MVDS_ROUTE_GROUND, 0x1000, 0x3000);
        mvds_observe_route(MVDS_ROUTE_GROUND, 0x1000, 0x3000);
    } else if (strcmp(name, "stale-source") == 0) {
        char path[] = "data/Missions/unit.def";
        g_parse_trampoline = harness_parse_insert;
        g_insert_trampoline = harness_insert_noop;
        hook_parse((void *)(uintptr_t)0x1000, 0, 7, path);
        hook_insert((void *)(uintptr_t)0x1000, 0, (void *)(uintptr_t)0x2000);
    } else if (strcmp(name, "unreadable-source") == 0) {
        g_parse_trampoline = harness_parse_noop;
        hook_parse((void *)(uintptr_t)0x1000, 0, 7, (const char *)(uintptr_t)1);
    } else if (strcmp(name, "unterminated-source") == 0) {
        char path[PATH_CAP];
        memset(path, 'x', sizeof(path));
        g_parse_trampoline = harness_parse_noop;
        hook_parse((void *)(uintptr_t)0x1000, 0, 7, path);
    } else if (strcmp(name, "nested-source") == 0) {
        char path[] = "data/Missions/unit.def";
        g_parse_trampoline = harness_parse_nested;
        hook_parse((void *)(uintptr_t)0x1000, 0, 7, path);
    } else if (strcmp(name, "duplicate-action") == 0) {
        DWORD node[9] = {0};
        node[4] = 0x3000;
        g_action.active = TRUE;
        g_action.node = (DWORD)(uintptr_t)node;
        capture_action(MVDS_ROUTE_GROUND, (DWORD)(uintptr_t)node, 0x2000);
    } else if (strcmp(name, "duplicate-outro-commit") == 0) {
        g_action.active = TRUE;
        g_action.expected_route = MVDS_ROUTE_LOCATION_POLICY;
        g_action.expected_object = 0x1000;
        capture_outro_commit(0x1000);
        capture_outro_commit(0x1000);
    } else if (strcmp(name, "wrong-outro-object") == 0) {
        g_action.active = TRUE;
        g_action.expected_route = MVDS_ROUTE_LOCATION_POLICY;
        g_action.expected_object = 0x1000;
        capture_outro_commit(0x2000);
    } else if (strcmp(name, "wrong-generic-probe-object") == 0) {
        begin_selector(SELECTOR_GENERIC, (void *)(uintptr_t)0x1000);
        capture_selector_site(SITE_GENERIC_FINAL_PRESENT, 0x2000, 0);
    } else if (strcmp(name, "wrong-grotte-probe-object") == 0) {
        begin_selector(SELECTOR_GROTTE, (void *)(uintptr_t)0x1000);
        capture_selector_site(SITE_GROTTE_REFUEL, 0x2000, 0);
    } else if (strcmp(name, "wrong-raymond-entry-probe-object") == 0) {
        begin_selector(SELECTOR_RAYMOND_ENTRY, (void *)(uintptr_t)0x1000);
        capture_selector_site(SITE_RAYMOND_FIRST, 0x2000, 0);
    } else if (strcmp(name, "wrong-raymond-result-probe-object") == 0) {
        begin_selector(SELECTOR_RAYMOND_RESULT, (void *)(uintptr_t)0x1000);
        capture_selector_site(SITE_RAYMOND_RESULT, 0x2000, 0);
    } else if (strcmp(name, "wrong-exhibition-probe-object") == 0) {
        begin_selector(SELECTOR_EXHIBITION, (void *)(uintptr_t)0x1000);
        capture_selector_site(SITE_EXHIBITION_PROJECTION, 0x2000, 0);
    } else if (strcmp(name, "wrong-selector-kind") == 0) {
        begin_selector(SELECTOR_GROTTE, (void *)(uintptr_t)0x1000);
        capture_selector_site(SITE_RAYMOND_FIRST, 0x1000, 0);
    } else if (strcmp(name, "unreadable-semantic-object") == 0) {
        (void)read_u32(1);
    } else if (strcmp(name, "mygghanget-queued-root") == 0 ||
        strcmp(name, "mygghanget-default-root") == 0 ||
        strcmp(name, "mygghanget-active-root") == 0) {
        DWORD object[0x900 / sizeof(DWORD)] = {0};
        SelectorFrame completed = {0};
        DWORD offset = strcmp(name, "mygghanget-queued-root") == 0 ? 0x8c8 :
            strcmp(name, "mygghanget-default-root") == 0 ? 0x8d0 : 0x8d4;
        object[offset / sizeof(DWORD)] = 0x3000;
        (void)mygghanget_absence_is_proven(
            &completed, (DWORD)(uintptr_t)object
        );
    } else if (strcmp(name, "mygghanget-new-root") == 0) {
        DWORD object[0x900 / sizeof(DWORD)] = {0};
        SelectorFrame completed = {0};
        completed.mygghanget_root_created = TRUE;
        (void)mygghanget_absence_is_proven(
            &completed, (DWORD)(uintptr_t)object
        );
    } else if (strcmp(name, "mygghanget-factory-provenance") == 0) {
        DWORD object[0x900 / sizeof(DWORD)] = {0};
        SelectorFrame completed;
        char invalid_path[] = "not-a-canonical-location-script";
        g_root_factory_trampoline = harness_root_factory;
        begin_selector(SELECTOR_MYGGHANGET, object);
        SetLastError(0x4321);
        (void)hook_root_factory(NULL, invalid_path);
        if (GetLastError() != 0x1234) return 9;
        completed = g_selector;
        end_selector();
        if (!completed.root_without_provenance) return 10;
        (void)mygghanget_absence_is_proven(
            &completed, (DWORD)(uintptr_t)object
        );
    } else if (strcmp(name, "mygghanget-observed-route") == 0) {
        DWORD object[0x900 / sizeof(DWORD)] = {0};
        SelectorFrame completed;
        begin_selector(SELECTOR_MYGGHANGET, object);
        mvds_observe_route(
            MVDS_ROUTE_GROUND, (DWORD)(uintptr_t)object, 0
        );
        completed = g_selector;
        end_selector();
        (void)mygghanget_absence_is_proven(
            &completed, (DWORD)(uintptr_t)object
        );
    } else {
        return 4;
    }
    return g_fatal ? 0 : 5;
}

int main(int argc, char **argv) {
    MvdsCaptureTarget target = {0};
    memset(&g_host, 0, sizeof(g_host));
    g_host.emit_line = harness_emit;
    g_host.fail_closed = harness_fail;
    g_host.capture_completed = harness_capture_complete;
    g_host.capture_plan_job_id = "unit/native-dispatch";
    g_host.native_slice_sha256 =
        "1111111111111111111111111111111111111111111111111111111111111111";
    g_host.observer_binary_sha256 =
        "2222222222222222222222222222222222222222222222222222222222222222";
    g_host.observer_build_receipt_sha256 =
        "3333333333333333333333333333333333333333333333333333333333333333";
    target.evidence_class = MVDS_EVIDENCE_LOCATION_POLICY;
    target.plan_manifest_sha256 =
        "4444444444444444444444444444444444444444444444444444444444444444";
    target.capture_plan_sha256 =
        "5555555555555555555555555555555555555555555555555555555555555555";
    target.job_id = "unit/native-dispatch";
    target.job_sha256 =
        "6666666666666666666666666666666666666666666666666666666666666666";
    target.claim_id = "unit/native-dispatch-claim";
    target.claim_sha256 =
        "7777777777777777777777777777777777777777777777777777777777777777";
    target.subject_sha256 =
        "8888888888888888888888888888888888888888888888888888888888888888";
    target.expectation_sha256 =
        "9999999999999999999999999999999999999999999999999999999999999999";
    target.scenario_sha256 =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    target.native_slice_sha256 = g_host.native_slice_sha256;
    target.target_sha256 =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    target.trigger.location.location_id = 1;
    target.trigger.location.selector = "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3";
    target.trigger.location.hook_family = MVDS_CAPTURE_HOOK_GENERIC_LOCATION_ENTER;
    target.trigger.location.event_argument = -1;
    if (!mvds_configure_capture_target(&target)) return 2;
    if (argc == 2 && strncmp(argv[1], "hook-plan-", 10) == 0) {
        return run_hook_plan_contract(argv[1]);
    }
    strcpy(g_capture_plan_job_id, "unit/native-dispatch");
    strcpy(g_native_slice_sha256, "1111111111111111111111111111111111111111111111111111111111111111");
    strcpy(g_observer_binary_sha256, "2222222222222222222222222222222222222222222222222222222222222222");
    strcpy(g_observer_build_receipt_sha256, "3333333333333333333333333333333333333333333333333333333333333333");
    InitializeCriticalSection(&g_lock);
    g_lock_initialized = TRUE;
    g_armed = TRUE;
    if (!mvds_bind_engine_thread(GetCurrentThreadId())) return 2;
    if (argc == 2 && strcmp(argv[1], "capability-drop") == 0) {
        g_drop_capability = TRUE;
        g_target_hook_open_authorized = TRUE;
        return !mvds_begin_capture_window() && g_fatal ? 0 : 6;
    }
    if (argc == 2 && strcmp(argv[1], "event-drop") == 0)
        g_drop_event = TRUE;
    g_target_hook_open_authorized = TRUE;
    if (!mvds_begin_capture_window()) return 2;
    g_target_hook_open_authorized = FALSE;
    if (g_drop_event) {
        emit_generic_location(
            "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3", 1, 0,
            "LOCATION_SCRIPT:roy_mccoy/stand");
        return g_fatal && !g_capture_event_emitted &&
            !mvds_end_capture_window() ? 0 : 7;
    }
    if (argc == 2 && strcmp(argv[1], "reuse-window") == 0) {
        MvdsHost rearm = g_host;
        emit_generic_location(
            "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3", 1, 0,
            "LOCATION_SCRIPT:roy_mccoy/stand");
        mvds_disable();
        return g_capture_window_consumed && !mvds_arm(&rearm, TRUE) ? 0 : 8;
    }
    if (argc == 2) return run_negative(argv[1]);
    emit_generic_location(
        "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3", 1, 0,
        "LOCATION_SCRIPT:roy_mccoy/stand");
    emit_generic_location(
        "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3", 1, 3,
        "LOCATION_SCRIPT:roy_mccoy/stand");
    emit_location_event(
        "ROOT_COMPLETE_REFUEL_ARMED_AND_UNCONSUMED", 10,
        "LOCATION_SCRIPT:grotte_grundlig/talk", TRUE,
        0, 0, 0, 1, 0, 0, FALSE, 0.0f, "ADVANCED");
    emit_location_event(
        "LOCATION_ENTER_FIRST_CHALLENGE", 20,
        "LOCATION_SCRIPT:raymond_rajser/challenge", FALSE,
        0, 1, 0, 0, 0, 0, FALSE, 0.0f, "STARTED");
    emit_location_event(
        "LOCATION_ENTER_SUBSEQUENT_CHALLENGE", 20,
        "LOCATION_SCRIPT:raymond_rajser/challenge", FALSE,
        0, 0, 0, 0, 0, 0, FALSE, 0.0f, "STARTED");
    emit_location_event(
        "CHALLENGE_ROOT_COMPLETE_RESULT_EQ_2", 20,
        "LOCATION_SCRIPT:raymond_rajser/mulle_win", TRUE,
        0, 0, 2, 0, 0, 0, FALSE, 0.0f, "ADVANCED");
    emit_location_event(
        "CHALLENGE_ROOT_COMPLETE_RESULT_NE_2", 20,
        "LOCATION_SCRIPT:raymond_rajser/mulle_lose", TRUE,
        0, 0, 1, 0, 0, 0, FALSE, 0.0f, "ADVANCED");
    emit_location_event(
        "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_LT_900", 14,
        "LOCATION_SCRIPT:varldsutstallning/judge", FALSE,
        0, 0, 0, 0, 0, 0, TRUE, 899.5f, "STARTED");
    emit_location_event(
        "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_NE_3", 14,
        "LOCATION_SCRIPT:varldsutstallning/emma", FALSE,
        0, 0, 0, 0, 0, 0, TRUE, 900.0f, "STARTED");
    emit_location_event(
        "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_EQ_3", 14,
        "LOCATION_SCRIPT:varldsutstallning/emma_final", FALSE,
        3, 0, 0, 0, 0, 0, TRUE, 900.0f, "STARTED");
    emit_location_event(
        "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_NE_3", 14,
        "LOCATION_SCRIPT:varldsutstallning/circus", FALSE,
        0, 0, 0, 0, 0, 0, TRUE, 2200.0f, "STARTED");
    emit_location_event(
        "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_EQ_3", 14,
        "LOCATION_SCRIPT:varldsutstallning/circus_final", FALSE,
        3, 0, 0, 0, 0, 0, TRUE, 2200.0f, "STARTED");
    emit_location_event(
        "LOCATION_ENTER_OUTRO_REQUESTED", 14,
        "LOCATION_SCRIPT:varldsutstallning/outro", FALSE,
        0, 0, 0, 0, 0, 1, FALSE, 0.0f, "STARTED");
    emit_location_event(
        "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE", 22, NULL, FALSE,
        0, 0, 0, 0, 0, 0, FALSE, 0.0f, "EXPECTED_ABSENCE");
    return g_fatal ? 3 : 0;
}
