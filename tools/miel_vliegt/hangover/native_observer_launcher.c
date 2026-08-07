#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "native_scenes.generated.h"
#include "native_dispatch_semantic_hook.h"
#include "native_sha256.h"

#define OBSERVER_BOOTSTRAP_STRATEGY "dinput-post-loader-worker-or-call-bootstrap"
#define INPUT_IDLE_PROBE_TIMEOUT_MS 0u
#define PROXY_BOOTSTRAP_TIMEOUT_MS 600000u

/*
 * Debugger-independent bootstrap for the pinned Win32 flight projector.
 * The disposable target is a byte-identical copy of the pinned executable;
 * the unmodified-start receipt proves that no startup-mode patch was applied.
 * DINPUT.dll is a first-party proxy loaded by the pinned projector.  A worker
 * released only after loader lock waits for Cc.dll and initializes the
 * observer. DirectInputCreateA remains a synchronous fallback before calling
 * the real DirectInput entry. The launcher owns the observer rendezvous events
 * before resuming the target; the hook then proves the transient pending-login
 * state and later login activation on manager ticks. No live code patching or
 * translated thread-context mutation is involved.
 */

typedef struct Options {
    const char *source;
    const char *target;
    const char *observer;
    const char *real_dinput;
    const char *patch_receipt;
    const char *receipt;
    const char *cwd;
    const char *scene;
    DWORD observe_ms;
} Options;

typedef struct Evidence {
    char source_sha256[65];
    char target_sha256[65];
    char observer_sha256[65];
    char real_dinput_sha256[65];
    char patch_receipt_sha256[65];
    BOOL created_suspended;
    BOOL loader_initialization_completed;
    BOOL proxy_observer_ready;
    BOOL observer_loaded;
    BOOL observer_initialized;
    BOOL login_pending_observed;
    BOOL ready_before_login_pending;
    BOOL login_activation_observed;
    BOOL ready_before_login_activation;
    BOOL message_loop_wake_posted;
    BOOL main_thread_resumed;
    DWORD main_thread_resume_count;
    BOOL projector_input_idle;
    BOOL scenario_completion_event;
    BOOL observer_failure_event_clear;
    BOOL observation_window_completed;
    BOOL target_terminated;
    BOOL native_dispatch_requested;
    BOOL native_dispatch_completion_event;
    DWORD native_process_id;
    char capture_session_id[MVDS_CAPTURE_SESSION_CAP];
} Evidence;

typedef struct ObserverEvents {
    HANDLE complete;
    HANDLE failure;
    HANDLE ready;
    HANDLE pending;
    HANDLE activation;
    HANDLE native_dispatch_complete;
    HANDLE identity_mapping;
    MvdsSharedProcessIdentity *shared_identity;
} ObserverEvents;

static void write_receipt(const Options *options, const Evidence *evidence,
                          const char *status, const char *phase,
                          const char *detail)
{
    FILE *stream;
    char capture_process[192];
    if (!options->receipt) return;
    if (evidence->native_process_id != 0u && evidence->capture_session_id[0]) {
        snprintf(capture_process,sizeof(capture_process),
            "{\"native_process_id\":%lu,\"capture_session_id\":\"%s\"}",
            (unsigned long)evidence->native_process_id,
            evidence->capture_session_id);
    } else strcpy(capture_process,"null");
    stream = fopen(options->receipt, "wb");
    if (!stream) return;
    fprintf(stream,
        "{\"schema\":1,\"protocol\":\"miel-vliegt-native-observer-launch\","
        "\"status\":\"%s\",\"phase\":\"%s\",\"detail\":\"%s\","
        "\"bootstrap_strategy\":\"" OBSERVER_BOOTSTRAP_STRATEGY "\","
        "\"input_idle_probe_timeout_ms\":%lu,"
        "\"proxy_bootstrap_timeout_ms\":%lu,"
        "\"scene\":\"%s\",\"original_executable_sha256\":\"%s\","
        "\"patched_executable_sha256\":\"%s\",\"observer_dll_sha256\":\"%s\","
        "\"real_dinput_sha256\":\"%s\","
        "\"patch_receipt_sha256\":\"%s\","
        "\"capture_process\":%s,"
        "\"checks\":{"
        "\"created_suspended\":%s,"
        "\"loader_initialization_completed\":%s,"
        "\"proxy_observer_ready\":%s,"
        "\"observer_loaded\":%s,"
        "\"observer_initialized\":%s,"
        "\"login_pending_observed\":%s,"
        "\"ready_before_login_pending\":%s,"
        "\"login_activation_observed\":%s,"
        "\"ready_before_login_activation\":%s,"
        "\"main_thread_resumed\":%s,"
        "\"main_thread_resume_count\":%lu,"
        "\"message_loop_wake_posted\":%s,"
        "\"projector_input_idle\":%s,\"scenario_completion_event\":%s,"
        "\"observer_failure_event_clear\":%s,"
        "\"native_dispatch_requested\":%s,"
        "\"native_dispatch_completion_event\":%s,"
        "\"observation_window_completed\":%s,"
        "\"target_terminated\":%s}}\n",
        status, phase, detail, (unsigned long)INPUT_IDLE_PROBE_TIMEOUT_MS,
        (unsigned long)PROXY_BOOTSTRAP_TIMEOUT_MS,
        options->scene ? options->scene : "",
        evidence->source_sha256, evidence->target_sha256,
        evidence->observer_sha256, evidence->real_dinput_sha256,
        evidence->patch_receipt_sha256,
        capture_process,
        evidence->created_suspended ? "true" : "false",
        evidence->loader_initialization_completed ? "true" : "false",
        evidence->proxy_observer_ready ? "true" : "false",
        evidence->observer_loaded ? "true" : "false",
        evidence->observer_initialized ? "true" : "false",
        evidence->login_pending_observed ? "true" : "false",
        evidence->ready_before_login_pending ? "true" : "false",
        evidence->login_activation_observed ? "true" : "false",
        evidence->ready_before_login_activation ? "true" : "false",
        evidence->main_thread_resumed ? "true" : "false",
        (unsigned long)evidence->main_thread_resume_count,
        evidence->message_loop_wake_posted ? "true" : "false",
        evidence->projector_input_idle ? "true" : "false",
        evidence->scenario_completion_event ? "true" : "false",
        evidence->observer_failure_event_clear ? "true" : "false",
        evidence->native_dispatch_requested ? "true" : "false",
        evidence->native_dispatch_completion_event ? "true" : "false",
        evidence->observation_window_completed ? "true" : "false",
        evidence->target_terminated ? "true" : "false");
    fclose(stream);
}

typedef struct WindowWakeContext {
    DWORD process_id;
    BOOL posted;
} WindowWakeContext;

static BOOL CALLBACK post_null_to_process_window(HWND window, LPARAM parameter)
{
    WindowWakeContext *context = (WindowWakeContext *)(ULONG_PTR)parameter;
    DWORD process_id = 0;
    GetWindowThreadProcessId(window, &process_id);
    if (process_id == context->process_id &&
        PostMessageA(window, WM_NULL, 0, 0)) context->posted = TRUE;
    return TRUE;
}

static BOOL wake_process_message_loop(const PROCESS_INFORMATION *process)
{
    WindowWakeContext context;
    BOOL thread_posted = PostThreadMessageA(
        process->dwThreadId, WM_NULL, 0, 0);
    context.process_id = process->dwProcessId;
    context.posted = FALSE;
    EnumWindows(post_null_to_process_window, (LPARAM)(ULONG_PTR)&context);
    return thread_posted || context.posted;
}

static BOOL create_observer_event(DWORD process_id, const char *kind,
                                  HANDLE *event_out)
{
    char name[96];
    int length = snprintf(
        name, sizeof(name), "Local\\MielObserver%s-%lu", kind,
        (unsigned long)process_id);
    if (length <= 0 || (size_t)length >= sizeof(name)) return FALSE;
    *event_out = CreateEventA(NULL, TRUE, FALSE, name);
    return *event_out != NULL && GetLastError() != ERROR_ALREADY_EXISTS;
}

static BOOL create_observer_events(DWORD process_id, ObserverEvents *events)
{
    memset(events, 0, sizeof(*events));
    return create_observer_event(process_id, "Complete", &events->complete) &&
        create_observer_event(process_id, "Failure", &events->failure) &&
        create_observer_event(process_id, "Ready", &events->ready) &&
        create_observer_event(process_id, "LoginPending", &events->pending) &&
        create_observer_event(
            process_id, "LoginActivated", &events->activation) &&
        create_observer_event(process_id, "NativeDispatchComplete",
                              &events->native_dispatch_complete);
}

static BOOL create_native_dispatch_identity_mapping(
    DWORD process_id, ObserverEvents *events
)
{
    char name[96];
    int length = snprintf(name,sizeof(name),MVDS_IDENTITY_MAPPING_PREFIX "%lu",
                          (unsigned long)process_id);
    if (length <= 0 || (size_t)length >= sizeof(name)) return FALSE;
    events->identity_mapping = CreateFileMappingA(
        INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,
        sizeof(MvdsSharedProcessIdentity),name);
    if (!events->identity_mapping || GetLastError() == ERROR_ALREADY_EXISTS) return FALSE;
    events->shared_identity = (MvdsSharedProcessIdentity *)MapViewOfFile(
        events->identity_mapping,FILE_MAP_READ | FILE_MAP_WRITE,0,0,
        sizeof(MvdsSharedProcessIdentity));
    if (!events->shared_identity) return FALSE;
    memset(events->shared_identity,0,sizeof(*events->shared_identity));
    return TRUE;
}

static void close_observer_events(ObserverEvents *events)
{
    if (events->shared_identity) UnmapViewOfFile(events->shared_identity);
    if (events->identity_mapping) CloseHandle(events->identity_mapping);
    if (events->native_dispatch_complete) CloseHandle(events->native_dispatch_complete);
    if (events->activation) CloseHandle(events->activation);
    if (events->pending) CloseHandle(events->pending);
    if (events->ready) CloseHandle(events->ready);
    if (events->failure) CloseHandle(events->failure);
    if (events->complete) CloseHandle(events->complete);
    memset(events, 0, sizeof(*events));
}

static BOOL collect_native_dispatch_identity(
    DWORD process_id, const ObserverEvents *events, Evidence *evidence
)
{
    const MvdsSharedProcessIdentity *identity = events->shared_identity;
    size_t length;
    if (!identity || identity->schema != 1u ||
        identity->native_process_id != process_id ||
        InterlockedCompareExchange((volatile LONG *)&identity->ready,0,0) != 1 ||
        InterlockedCompareExchange(
            (volatile LONG *)&identity->capture_complete,0,0) != 1) return FALSE;
    length = strlen(identity->capture_session_id);
    if (length != 37u || strncmp(identity->capture_session_id,"mvds-",5) != 0)
        return FALSE;
    evidence->native_process_id = process_id;
    strcpy(evidence->capture_session_id,identity->capture_session_id);
    return TRUE;
}

static DWORD wait_for_observer_result(const PROCESS_INFORMATION *process,
                                      DWORD timeout_ms, Evidence *evidence,
                                      const ObserverEvents *events)
{
    HANDLE handles[3];
    DWORD result = WAIT_FAILED;
    DWORD started = GetTickCount();
    handles[0] = evidence->native_dispatch_requested ?
        events->native_dispatch_complete : events->complete;
    handles[1] = events->failure;
    handles[2] = process->hProcess;
    do {
        DWORD elapsed = (DWORD)(GetTickCount() - started);
        DWORD remaining = elapsed < timeout_ms ? timeout_ms - elapsed : 0u;
        DWORD slice = remaining > 100u ? 100u : remaining;
        if (slice == 0u) {
            result = WAIT_TIMEOUT;
            break;
        }
        result = WaitForMultipleObjects(3, handles, FALSE, slice);
        if (result != WAIT_TIMEOUT) break;
        if (!wake_process_message_loop(process)) {
            result = WAIT_FAILED;
            break;
        }
    } while ((DWORD)(GetTickCount() - started) < timeout_ms);
    if (result == WAIT_OBJECT_0) {
        evidence->scenario_completion_event = TRUE;
        evidence->native_dispatch_completion_event =
            evidence->native_dispatch_requested;
        evidence->observer_failure_event_clear =
            WaitForSingleObject(events->failure, 0) == WAIT_TIMEOUT;
        if (evidence->native_dispatch_requested &&
            !collect_native_dispatch_identity(
                process->dwProcessId,events,evidence)) result = WAIT_FAILED;
    }
    return result;
}

static DWORD wait_for_proxy_bootstrap(const PROCESS_INFORMATION *process,
                                      DWORD timeout_ms, Evidence *evidence,
                                      const ObserverEvents *events)
{
    DWORD started = GetTickCount(), last_wake = started, result = WAIT_TIMEOUT;
    /* Clear any stale signaled state from a previous process with same PID */
    ResetEvent(events->failure);
    ResetEvent(events->ready);
    ResetEvent(events->pending);
    ResetEvent(events->activation);
    ResetEvent(events->complete);
    do {
        if (WaitForSingleObject(events->failure, 0u) == WAIT_OBJECT_0) {
            result = WAIT_OBJECT_0 + 1u;
            break;
        }
        if (!evidence->projector_input_idle &&
            WaitForInputIdle(
                process->hProcess, INPUT_IDLE_PROBE_TIMEOUT_MS) == 0u) {
            evidence->projector_input_idle = TRUE;
        }
        if (WaitForSingleObject(events->ready, 0u) == WAIT_OBJECT_0) {
            evidence->proxy_observer_ready = TRUE;
            evidence->loader_initialization_completed = TRUE;
            evidence->observer_loaded = TRUE;
            evidence->observer_initialized = TRUE;
        }
        if (WaitForSingleObject(events->pending, 0u) == WAIT_OBJECT_0) {
            if (!evidence->proxy_observer_ready) {
                result = WAIT_OBJECT_0 + 1u;
                break;
            }
            evidence->login_pending_observed = TRUE;
            evidence->ready_before_login_pending = TRUE;
        }
        if (WaitForSingleObject(events->activation, 0u) == WAIT_OBJECT_0) {
            evidence->login_activation_observed = TRUE;
            if (!evidence->login_pending_observed ||
                !evidence->proxy_observer_ready) {
                result = WAIT_OBJECT_0 + 1u;
                break;
            }
            evidence->ready_before_login_activation = TRUE;
            result = WAIT_OBJECT_0;
            break;
        }
        if (WaitForSingleObject(process->hProcess, 0u) == WAIT_OBJECT_0) {
            result = WAIT_OBJECT_0 + 2u;
            break;
        }
        if (evidence->proxy_observer_ready &&
            evidence->login_pending_observed &&
            (DWORD)(GetTickCount() - last_wake) >= 100u) {
            /* Only drive the GUI loop after the observer has proven the
               pending-login boundary. Activation remains a separate native
               manager-tick event and therefore cannot be forged by this wake. */
            if (wake_process_message_loop(process)) {
                evidence->message_loop_wake_posted = TRUE;
            }
            last_wake = GetTickCount();
        }
        Sleep(1u);
    } while ((DWORD)(GetTickCount() - started) < timeout_ms);
    return result;
}

typedef struct EnvironmentSnapshot {
    const char *name;
    char *value;
    BOOL existed;
} EnvironmentSnapshot;

static BOOL capture_environment(
    const char *name, EnvironmentSnapshot *snapshot
)
{
    DWORD length, error;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->name = name;
    SetLastError(ERROR_SUCCESS);
    length = GetEnvironmentVariableA(name, NULL, 0u);
    error = GetLastError();
    if (length == 0u) {
        if (error == ERROR_ENVVAR_NOT_FOUND) return TRUE;
        if (error != ERROR_SUCCESS) return FALSE;
        snapshot->value = (char *)malloc(1u);
        if (!snapshot->value) return FALSE;
        snapshot->value[0] = '\0';
        snapshot->existed = TRUE;
        return TRUE;
    }
    snapshot->value = (char *)malloc((size_t)length);
    if (!snapshot->value) return FALSE;
    if (GetEnvironmentVariableA(name, snapshot->value, length) != length - 1u) {
        free(snapshot->value);
        snapshot->value = NULL;
        return FALSE;
    }
    snapshot->existed = TRUE;
    return TRUE;
}

static BOOL restore_child_environment(
    EnvironmentSnapshot snapshots[3]
)
{
    BOOL ok = TRUE;
    int index;
    for (index = 2; index >= 0; --index) {
        if (snapshots[index].name &&
            !SetEnvironmentVariableA(
                snapshots[index].name,
                snapshots[index].existed ? snapshots[index].value : NULL)) {
            ok = FALSE;
        }
        free(snapshots[index].value);
        memset(&snapshots[index], 0, sizeof(snapshots[index]));
    }
    return ok;
}

static BOOL set_child_environment(
    const Options *options, EnvironmentSnapshot snapshots[3]
)
{
    static const char *const names[3] = {
        "MIEL_OBSERVER_EVENTS_PREOWNED",
        "MIEL_REAL_DINPUT",
        "MIEL_OBSERVER_DLL",
    };
    const char *values[3];
    unsigned index;
    memset(snapshots, 0, sizeof(EnvironmentSnapshot) * 3u);
    values[0] = "1";
    values[1] = options->real_dinput;
    /* Wine: strip path so LoadLibrary searches the exe directory.
       Wine's LoadLibrary doesn't reliably load DLLs from Z:\ paths. */
    {
        const char *obs = options->observer;
        const char *bs = strrchr(obs, '\\');
        const char *fs = strrchr(obs, '/');
        const char *last = (bs > fs) ? bs : fs;
        values[2] = last ? last + 1 : obs;
    }
    for (index = 0; index < 3u; ++index) {
        if (!capture_environment(names[index], &snapshots[index])) {
            restore_child_environment(snapshots);
            return FALSE;
        }
    }
    for (index = 0; index < 3u; ++index) {
        if (!SetEnvironmentVariableA(names[index], values[index])) {
            restore_child_environment(snapshots);
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL parse_options(int argc, char **argv, Options *options)
{
    int index;
    memset(options, 0, sizeof(*options));
    options->observe_ms = 10000;
    for (index = 1; index < argc; ++index) {
        const char *name = argv[index];
        const char *value;
        unsigned long duration;
        char *end = NULL;
        if (index + 1 >= argc) return FALSE;
        value = argv[++index];
        if (!strcmp(name, "--source")) options->source = value;
        else if (!strcmp(name, "--target")) options->target = value;
        else if (!strcmp(name, "--observer")) options->observer = value;
        else if (!strcmp(name, "--real-dinput")) options->real_dinput = value;
        else if (!strcmp(name, "--patch-receipt")) options->patch_receipt = value;
        else if (!strcmp(name, "--receipt")) options->receipt = value;
        else if (!strcmp(name, "--cwd")) options->cwd = value;
        else if (!strcmp(name, "--scene")) options->scene = value;
        else if (!strcmp(name, "--observe-ms")) {
            duration = strtoul(value, &end, 10);
            if (!end || *end || duration < 1000 || duration > 3600000) return FALSE;
            options->observe_ms = (DWORD)duration;
        } else return FALSE;
    }
    return options->source && options->target && options->observer &&
        options->real_dinput &&
        options->patch_receipt && options->receipt && options->scene;
}

static void terminate_failed_target(const Options *options, Evidence *evidence,
                                    PROCESS_INFORMATION *process,
                                    const char *phase, const char *detail)
{
    if (TerminateProcess(process->hProcess, 5u) &&
        WaitForSingleObject(process->hProcess, 5000u) == WAIT_OBJECT_0) {
        evidence->target_terminated = TRUE;
    }
    write_receipt(options, evidence, "FAIL", phase, detail);
}

int main(int argc, char **argv)
{
    Options options;
    Evidence evidence;
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    ObserverEvents observer_events;
    char command_line[MAX_PATH * 2];
    DWORD wait_result;
    BOOL ok = FALSE;
    char native_dispatch[2] = {0};
    DWORD native_dispatch_length;
    EnvironmentSnapshot child_environment[3];
    BOOL process_created, environment_restored;
    memset(&evidence, 0, sizeof(evidence));
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    memset(&observer_events, 0, sizeof(observer_events));
    memset(child_environment, 0, sizeof(child_environment));
    startup.cb = sizeof(startup);
    if (!parse_options(argc, argv, &options)) {
        fprintf(stderr, "usage: native-observer-launcher --source ORIGINAL --target DISPOSABLE_COPY --observer DLL --real-dinput DLL --patch-receipt UNMODIFIED_START_JSON --receipt JSON --scene ID [--cwd DIR] [--observe-ms N]\n");
        return 2;
    }
    native_dispatch_length = GetEnvironmentVariableA(
        "MIEL_OBSERVER_NATIVE_DISPATCH",native_dispatch,
        sizeof(native_dispatch));
    evidence.native_dispatch_requested = native_dispatch_length == 1u &&
        native_dispatch[0] == '1';
    if (native_dispatch_length != 0u && !evidence.native_dispatch_requested) {
        write_receipt(&options,&evidence,"FAIL","preflight",
                      "native-dispatch-environment-invalid");
        return 3;
    }
    if (!miel_sha256_file(options.source, evidence.source_sha256)) {
        write_receipt(&options,&evidence,"FAIL","preflight",
                      "source-hash-read-failed");
        return 3;
    }
    if (strcmp(evidence.source_sha256, MIEL_EXPECTED_EXE_SHA256)) {
        write_receipt(&options,&evidence,"FAIL","preflight",
                      "source-identity-mismatch");
        return 3;
    }
    if (!miel_sha256_file(options.target, evidence.target_sha256)) {
        write_receipt(&options,&evidence,"FAIL","preflight",
                      "target-hash-read-failed");
        return 3;
    }
    if (!miel_sha256_file(options.observer, evidence.observer_sha256)) {
        write_receipt(&options,&evidence,"FAIL","preflight",
                      "observer-hash-read-failed");
        return 3;
    }
    if (!miel_sha256_file(options.real_dinput,evidence.real_dinput_sha256)) {
        write_receipt(&options,&evidence,"FAIL","preflight",
                      "real-dinput-hash-read-failed");
        return 3;
    }
    if (!miel_sha256_file(
            options.patch_receipt,evidence.patch_receipt_sha256)) {
        write_receipt(&options,&evidence,"FAIL","preflight",
                      "patch-receipt-hash-read-failed");
        return 3;
    }
    snprintf(command_line, sizeof(command_line), "\"%s\"", options.target);
    if (!set_child_environment(&options, child_environment)) {
        write_receipt(&options, &evidence, "FAIL", "preflight",
                      "child-environment-binding-failed");
        return 4;
    }
    /* On native Windows, use CREATE_SUSPENDED to give the DINPUT proxy's
       bootstrap thread time to detect Cc.dll and initialize the observer
       before the game's main loop runs and potentially exits.
       On Wine, CREATE_SUSPENDED can cause issues, so use 0. */
    HMODULE ntdll_mod = GetModuleHandleA("ntdll.dll");
    BOOL running_on_wine = ntdll_mod &&
        GetProcAddress(ntdll_mod, "wine_get_version") != NULL;
    DWORD creation_flags = running_on_wine ? 0 : CREATE_SUSPENDED;
    process_created = CreateProcessA(
        options.target, command_line, NULL, NULL, TRUE, creation_flags,
        NULL, options.cwd, &startup, &process);
    environment_restored = restore_child_environment(child_environment);
    if (!process_created) {
        write_receipt(&options, &evidence, "FAIL", "create-process", "create-suspended-failed");
        return 4;
    }
    if (!environment_restored) {
        if (TerminateProcess(process.hProcess, 5u) &&
            WaitForSingleObject(process.hProcess, 5000u) == WAIT_OBJECT_0) {
            evidence.target_terminated = TRUE;
        }
        write_receipt(&options, &evidence, "FAIL", "create-process",
                      "child-environment-restore-failed");
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 4;
    }
    evidence.created_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
    if (!create_observer_events(process.dwProcessId, &observer_events)) {
        terminate_failed_target(&options, &evidence, &process, "events",
                                "preowned-observer-events-failed");
        goto done;
    }
    if (evidence.native_dispatch_requested &&
        !create_native_dispatch_identity_mapping(
            process.dwProcessId,&observer_events)) {
        terminate_failed_target(&options,&evidence,&process,"identity",
                                "native-dispatch-identity-mapping-failed");
        goto done;
    }
    /* Only call ResumeThread if we used CREATE_SUSPENDED */
    if (creation_flags & CREATE_SUSPENDED) {
        if (ResumeThread(process.hThread) == (DWORD)-1) {
        terminate_failed_target(&options, &evidence, &process, "resume",
                                "unexpected-suspend-count");
            goto done;
        }
    }
    evidence.main_thread_resumed = TRUE;
    evidence.main_thread_resume_count = 1u;
    /* The post-loader worker must establish observer readiness independently
       of GUI idleness. Poll both facts together so a continuously busy
       projector cannot consume the scenario observation budget before the
       proxy rendezvous has even been proven. */
    wait_result = wait_for_proxy_bootstrap(
        &process, PROXY_BOOTSTRAP_TIMEOUT_MS, &evidence, &observer_events);
    if (wait_result == WAIT_OBJECT_0 + 1u) {
        terminate_failed_target(&options, &evidence, &process, "proxy",
                                "observer-or-login-lifecycle-failed");
        goto done;
    }
    if (wait_result == WAIT_OBJECT_0 + 2u) {
        write_receipt(&options, &evidence, "FAIL", "proxy",
                      "target-exited-before-proxy-bootstrap");
        goto done;
    }
    if (wait_result == WAIT_TIMEOUT) {
        terminate_failed_target(&options, &evidence, &process, "proxy",
                                "proxy-bootstrap-timeout");
        goto done;
    }
    if (wait_result != WAIT_OBJECT_0) {
        terminate_failed_target(&options, &evidence, &process, "proxy",
                                "proxy-bootstrap-invalid");
        goto done;
    }
    wait_result = wait_for_observer_result(
        &process, options.observe_ms, &evidence, &observer_events);
    if (wait_result == WAIT_OBJECT_0 + 1) {
        terminate_failed_target(&options, &evidence, &process, "scenario",
                                "observer-reported-failure");
        goto done;
    }
    if (wait_result == WAIT_OBJECT_0 + 2) {
        write_receipt(&options, &evidence, "FAIL", "scenario", "target-exited-before-completion");
        goto done;
    }
    if (wait_result == WAIT_TIMEOUT) {
        terminate_failed_target(&options, &evidence, &process, "scenario",
                                "scenario-completion-timeout");
        goto done;
    }
    if (wait_result != WAIT_OBJECT_0 || !evidence.observer_failure_event_clear) {
        terminate_failed_target(&options, &evidence, &process, "scenario",
                                "completion-event-invalid");
        goto done;
    }
    evidence.observation_window_completed = TRUE;
    if (!TerminateProcess(process.hProcess, 0) ||
        WaitForSingleObject(process.hProcess, 5000) != WAIT_OBJECT_0) {
        write_receipt(&options, &evidence, "FAIL", "cleanup", "target-termination-failed");
        goto done;
    }
    evidence.target_terminated = TRUE;
    write_receipt(&options, &evidence, "PASS", "cleanup",
                  "observer-bootstrap-complete");
    ok = TRUE;
done:
    if (!evidence.target_terminated) WaitForSingleObject(process.hProcess, 5000);
    close_observer_events(&observer_events);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return ok ? 0 : 5;
}
