#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "native_scenes.generated.h"
#include "native_sha256.h"

/*
 * Small PE32 debugger controller for the original game.  It does not know or
 * patch a guessed "current location" field.  It observes the original mode
 * registry, replaces one normal SetMode argument, and confirms the matching
 * location loader.  Hangover loses cross-process EIP redirects while bridging
 * guest exceptions, so every breakpoint is one-shot and resumes only after
 * restoring the original bytes at the same program counter.  Runtime commands
 * fail closed until an in-process game-thread hook is available.
 */

typedef enum BreakpointKind {
    BP_NONE = 0,
    BP_REGISTRATION,
    BP_MODE_CHANGE,
    BP_LOADER
} BreakpointKind;

typedef enum TrapStrategy {
    TRAP_INT3 = 0,
    TRAP_UD2
} TrapStrategy;

typedef struct Breakpoint {
    BreakpointKind kind;
    DWORD address;
    BYTE original[16];
    SIZE_T stolen_size;
    BOOL action_pending;
    BOOL armed;
} Breakpoint;

typedef struct Options {
    const char *target;
    const char *scene;
    const char *receipt;
    const char *cwd;
    const char *observer;
    TrapStrategy trap;
    BOOL quit_on_confirm;
} Options;

static HANDLE process_handle;
static HANDLE initial_thread_handle;
static DWORD mode_manager;
static const MielSceneSpec *requested_scene;
static Breakpoint registration_breakpoint;
static Breakpoint mode_breakpoint;
static Breakpoint loader_breakpoints[MIEL_SCENE_COUNT];
static Breakpoint *pending_loader_breakpoint;
static unsigned request_sequence;
static BOOL observer_injected;
static char observer_sha256[65];
#define MAX_SUSPENDED_THREADS 256
static HANDLE suspended_threads[MAX_SUSPENDED_THREADS];
static unsigned suspended_thread_count;
static TrapStrategy trap_strategy = TRAP_INT3;

static const char *trap_name(TrapStrategy strategy)
{
    return strategy == TRAP_UD2 ? "ud2" : "int3";
}

static SIZE_T trap_size(void)
{
    return trap_strategy == TRAP_UD2 ? 2 : 1;
}

static DWORD trap_exception_code(void)
{
    return trap_strategy == TRAP_UD2 ? EXCEPTION_ILLEGAL_INSTRUCTION : EXCEPTION_BREAKPOINT;
}

static const BYTE *trap_bytes(void)
{
    static const BYTE int3[] = {0xcc};
    static const BYTE ud2[] = {0x0f, 0x0b};
    return trap_strategy == TRAP_UD2 ? ud2 : int3;
}

static const MielSceneSpec *find_scene(const char *id)
{
    unsigned index;
    for (index = 0; index < MIEL_SCENE_COUNT; ++index)
        if (!strcmp(MIEL_SCENES[index].id, id)) return &MIEL_SCENES[index];
    return NULL;
}

static void write_receipt(const Options *options, const char *status, const char *phase, const char *detail)
{
    FILE *stream;
    if (!options->receipt) return;
    stream = fopen(options->receipt, "wb");
    if (!stream) return;
    fprintf(stream,
        "{\"schema\":1,\"protocol\":\"miel-vliegt-native-scene-navigation\","
        "\"status\":\"%s\",\"phase\":\"%s\",\"detail\":\"%s\","
        "\"trap_strategy\":\"%s\","
        "\"executable_sha256\":\"%s\",\"request_sequence\":%u,"
        "\"observer_injected\":%s,\"observer_dll_sha256\":\"%s\","
        "\"scene\":{\"id\":\"%s\",\"location_id\":%u,\"mode\":\"%s\"},"
        "\"mode_manager_observed\":%s}\n",
        status, phase, detail ? detail : "", trap_name(options->trap),
        MIEL_EXPECTED_EXE_SHA256, request_sequence,
        observer_injected ? "true" : "false", observer_sha256,
        requested_scene ? requested_scene->id : "", requested_scene ? requested_scene->location_id : 0,
        requested_scene ? requested_scene->mode : "", mode_manager ? "true" : "false");
    fclose(stream);
}

static BOOL read_exact(DWORD address, void *buffer, SIZE_T size)
{
    SIZE_T read = 0;
    return ReadProcessMemory(process_handle, (LPCVOID)(ULONG_PTR)address, buffer, size, &read) && read == size;
}

static BOOL write_exact(DWORD address, const void *buffer, SIZE_T size)
{
    SIZE_T written = 0;
    if (!WriteProcessMemory(process_handle, (LPVOID)(ULONG_PTR)address, buffer, size, &written) || written != size)
        return FALSE;
    return FlushInstructionCache(process_handle, (LPCVOID)(ULONG_PTR)address, size);
}

static ULONG_PTR remote_module_base(DWORD process_id, const char *module_name)
{
    MODULEENTRY32 entry;
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
    ULONG_PTR result = 0;
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Module32First(snapshot, &entry)) {
        do {
            if (!_stricmp(entry.szModule, module_name)) {
                result = (ULONG_PTR)entry.modBaseAddr;
                break;
            }
        } while (Module32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

static HANDLE begin_observer_injection(DWORD process_id, const char *path,
                                       LPVOID *remote_path)
{
    HMODULE local_kernel = GetModuleHandleA("kernel32.dll");
    FARPROC local_load_library;
    ULONG_PTR remote_kernel, remote_load_library;
    SIZE_T size, written = 0;
    HANDLE thread;
    if (!local_kernel || !path || !path[0]) return NULL;
    local_load_library = GetProcAddress(local_kernel, "LoadLibraryA");
    remote_kernel = remote_module_base(process_id, "kernel32.dll");
    if (!local_load_library || !remote_kernel) return NULL;
    remote_load_library = remote_kernel +
        ((ULONG_PTR)local_load_library - (ULONG_PTR)local_kernel);
    size = strlen(path) + 1;
    *remote_path = VirtualAllocEx(
        process_handle, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*remote_path) return NULL;
    if (!WriteProcessMemory(process_handle, *remote_path, path, size, &written) ||
        written != size) {
        VirtualFreeEx(process_handle, *remote_path, 0, MEM_RELEASE);
        *remote_path = NULL;
        return NULL;
    }
    thread = CreateRemoteThread(
        process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)(ULONG_PTR)remote_load_library,
        *remote_path, 0, NULL);
    if (!thread) {
        VirtualFreeEx(process_handle, *remote_path, 0, MEM_RELEASE);
        *remote_path = NULL;
    }
    return thread;
}

static BOOL suspend_one_thread(DWORD thread_id)
{
    HANDLE thread;
    if (suspended_thread_count == MAX_SUSPENDED_THREADS) return FALSE;
    thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_id);
    if (!thread || SuspendThread(thread) == (DWORD)-1) {
        if (thread) CloseHandle(thread);
        return FALSE;
    }
    suspended_threads[suspended_thread_count++] = thread;
    return TRUE;
}

static BOOL suspend_process_threads(DWORD process_id, DWORD excluded_thread_id)
{
    THREADENTRY32 entry;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    BOOL ok = snapshot != INVALID_HANDLE_VALUE;
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (ok && Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != process_id ||
                entry.th32ThreadID == excluded_thread_id) continue;
            if (!suspend_one_thread(entry.th32ThreadID)) {
                ok = FALSE;
                break;
            }
        } while (Thread32Next(snapshot, &entry));
    } else {
        ok = FALSE;
    }
    if (snapshot != INVALID_HANDLE_VALUE) CloseHandle(snapshot);
    return ok;
}

static BOOL resume_process_threads(void)
{
    BOOL ok = TRUE;
    while (suspended_thread_count) {
        HANDLE thread = suspended_threads[--suspended_thread_count];
        if (ResumeThread(thread) == (DWORD)-1) ok = FALSE;
        CloseHandle(thread);
    }
    return ok;
}

static void close_suspended_thread_handles(void)
{
    while (suspended_thread_count)
        CloseHandle(suspended_threads[--suspended_thread_count]);
}

static BOOL finish_observer_load(HANDLE thread, LPVOID remote_path,
                                 DWORD *module_handle)
{
    DWORD wait_result = WaitForSingleObject(thread, 10000);
    BOOL signaled = wait_result == WAIT_OBJECT_0;
    BOOL ok = signaled && GetExitCodeThread(thread, module_handle) &&
        *module_handle != 0;
    CloseHandle(thread);
    /* The remote loader still owns this string on timeout.  The caller kills
     * the target on every failure, so only release it after a signaled exit. */
    if (signaled &&
        !VirtualFreeEx(process_handle, remote_path, 0, MEM_RELEASE)) ok = FALSE;
    return ok;
}

static BOOL initialize_observer(DWORD module_handle,
                                const char *observer_path)
{
    DWORD initialized = 0;
    HMODULE local_observer = NULL;
    FARPROC local_initialize;
    ULONG_PTR remote_initialize;
    HANDLE initialize_thread = NULL;
    BOOL ok = TRUE;
    local_observer = LoadLibraryExA(
        observer_path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    local_initialize = local_observer
        ? GetProcAddress(local_observer, "MielObserverInitialize") : NULL;
    if (!local_initialize && local_observer)
        local_initialize = GetProcAddress(
            local_observer, "MielObserverInitialize@4");
    if (!local_initialize) ok = FALSE;
    if (ok) {
        remote_initialize = (ULONG_PTR)module_handle +
            ((ULONG_PTR)local_initialize - (ULONG_PTR)local_observer);
        initialize_thread = CreateRemoteThread(
            process_handle, NULL, 0,
            (LPTHREAD_START_ROUTINE)(ULONG_PTR)remote_initialize,
            NULL, 0, NULL);
        ok = initialize_thread &&
            WaitForSingleObject(initialize_thread, 10000) == WAIT_OBJECT_0 &&
            GetExitCodeThread(initialize_thread, &initialized) && initialized == 1;
    }
    if (initialize_thread) CloseHandle(initialize_thread);
    if (local_observer) FreeLibrary(local_observer);
    observer_injected = ok;
    return ok;
}

static BOOL verify_signature(DWORD address, const BYTE *expected, SIZE_T size)
{
    BYTE actual[32];
    return size <= sizeof(actual) && read_exact(address, actual, size) && !memcmp(actual, expected, size);
}

static BOOL arm_breakpoint(Breakpoint *breakpoint, BreakpointKind kind, DWORD address,
                           SIZE_T stolen_size)
{
    const BYTE *trap = trap_bytes();
    SIZE_T size = trap_size();
    if (breakpoint->armed || stolen_size < size ||
        stolen_size > sizeof(breakpoint->original)) return FALSE;
    if (!read_exact(address, breakpoint->original, stolen_size)) return FALSE;
    if (!memcmp(breakpoint->original, trap, size) ||
        !write_exact(address, trap, size)) return FALSE;
    breakpoint->kind = kind;
    breakpoint->address = address;
    breakpoint->stolen_size = stolen_size;
    breakpoint->action_pending = TRUE;
    breakpoint->armed = TRUE;
    return TRUE;
}

static BOOL consume_breakpoint(Breakpoint *breakpoint, CONTEXT *context,
                               DWORD reported_exception_address, BOOL *first_hit)
{
    if (!breakpoint->armed ||
        context->Eip != breakpoint->address ||
        reported_exception_address != breakpoint->address) return FALSE;
    if (!write_exact(breakpoint->address, breakpoint->original,
                     breakpoint->stolen_size)) return FALSE;
    *first_hit = breakpoint->action_pending;
    breakpoint->action_pending = FALSE;
    breakpoint->armed = FALSE;
    return TRUE;
}

static SIZE_T scene_loader_stolen_size(const MielSceneSpec *scene)
{
    const BYTE *signature;
    if (!scene || scene->loader_signature_size < 2) return 0;
    signature = scene->loader_signature;
    if (signature[0] == 0x64 && signature[1] == 0xa1) return 6;
    if (signature[0] == 0x6a ||
        (signature[0] == 0x56 && signature[1] == 0x57)) return 2;
    return 0;
}

static BOOL arm_scene_loader(void)
{
    unsigned index;
    Breakpoint *available = NULL;
    SIZE_T stolen_size;
    if (!requested_scene) return FALSE;
    stolen_size = scene_loader_stolen_size(requested_scene);
    if (!stolen_size) return FALSE;
    for (index = 0; index < MIEL_SCENE_COUNT; ++index) {
        Breakpoint *breakpoint = &loader_breakpoints[index];
        if (breakpoint->armed && breakpoint->address == requested_scene->loader) {
            breakpoint->action_pending = TRUE;
            pending_loader_breakpoint = breakpoint;
            return TRUE;
        }
        if (!breakpoint->armed && !available) available = breakpoint;
    }
    if (!available) return FALSE;
    if (!verify_signature(requested_scene->loader, requested_scene->loader_signature,
                          requested_scene->loader_signature_size)) return FALSE;
    if (!arm_breakpoint(available, BP_LOADER, requested_scene->loader, stolen_size))
        return FALSE;
    pending_loader_breakpoint = available;
    return TRUE;
}

static BOOL loader_action_pending(void)
{
    unsigned index;
    for (index = 0; index < MIEL_SCENE_COUNT; ++index)
        if (loader_breakpoints[index].action_pending) return TRUE;
    return FALSE;
}

static BOOL consume_loader_breakpoint(CONTEXT *context,
                                      DWORD reported_exception_address,
                                      BOOL *first_hit)
{
    unsigned index;
    for (index = 0; index < MIEL_SCENE_COUNT; ++index) {
        if (consume_breakpoint(&loader_breakpoints[index], context,
                               reported_exception_address, first_hit)) {
            if (*first_hit && pending_loader_breakpoint == &loader_breakpoints[index])
                pending_loader_breakpoint = NULL;
            return TRUE;
        }
    }
    return FALSE;
}

static void close_create_process_handles(const CREATE_PROCESS_DEBUG_INFO *info)
{
    if (info->hFile) CloseHandle(info->hFile);
    if (info->hThread && info->hThread != initial_thread_handle)
        CloseHandle(info->hThread);
    if (initial_thread_handle) {
        CloseHandle(initial_thread_handle);
        initial_thread_handle = NULL;
    }
    if (info->hProcess && info->hProcess != process_handle)
        CloseHandle(info->hProcess);
}

static void close_create_thread_handle(const CREATE_THREAD_DEBUG_INFO *info)
{
    if (info->hThread) CloseHandle(info->hThread);
}

static BOOL continue_debug_event_checked(const Options *options,
                                         const DEBUG_EVENT *event,
                                         DWORD continue_status)
{
    if (ContinueDebugEvent(event->dwProcessId, event->dwThreadId,
                           continue_status)) return TRUE;
    write_receipt(options, "FAIL", "debugger", "continue-failed");
    return FALSE;
}

static BOOL parse_options(int argc, char **argv, Options *options)
{
    int index;
    memset(options, 0, sizeof(*options));
    options->trap = TRAP_INT3;
    for (index = 1; index < argc; ++index) {
        const char *name = argv[index];
        if (!strcmp(name, "--quit-on-confirm")) options->quit_on_confirm = TRUE;
        else if (index + 1 >= argc) return FALSE;
        else if (!strcmp(name, "--target")) options->target = argv[++index];
        else if (!strcmp(name, "--scene")) options->scene = argv[++index];
        else if (!strcmp(name, "--receipt")) options->receipt = argv[++index];
        else if (!strcmp(name, "--cwd")) options->cwd = argv[++index];
        else if (!strcmp(name, "--observer")) options->observer = argv[++index];
        else if (!strcmp(name, "--trap")) {
            const char *value = argv[++index];
            if (!strcmp(value, "int3")) options->trap = TRAP_INT3;
            else if (!strcmp(value, "ud2")) options->trap = TRAP_UD2;
            else return FALSE;
        }
        else return FALSE;
    }
    return options->target && options->scene;
}

int main(int argc, char **argv)
{
    Options options;
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    DEBUG_EVENT event;
    char command_line[MAX_PATH * 2], actual_hash[65];
    BOOL running = TRUE, confirmed = FALSE, fatal_failure = FALSE;
    BOOL initial_breakpoint_seen = FALSE;
    DWORD continue_status;
    if (!parse_options(argc, argv, &options)) {
        fprintf(stderr, "usage: native-scene-debugger --target EXE --scene ID [--trap int3|ud2] [--cwd DIR] [--receipt FILE] [--observer DLL] [--quit-on-confirm]\n");
        return 2;
    }
    trap_strategy = options.trap;
    requested_scene = find_scene(options.scene);
    if (!requested_scene) {
        fprintf(stderr, "unknown native scene: %s\n", options.scene);
        return 2;
    }
    if (!miel_sha256_file(options.target, actual_hash) || strcmp(actual_hash, MIEL_EXPECTED_EXE_SHA256)) {
        fprintf(stderr, "native executable hash mismatch\n");
        return 3;
    }
    observer_sha256[0] = '\0';
    if (options.observer && !miel_sha256_file(options.observer, observer_sha256)) {
        fprintf(stderr, "native observer hash failed\n");
        return 3;
    }
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.cb = sizeof(startup);
    snprintf(command_line, sizeof(command_line), "\"%s\"", options.target);
    if (!CreateProcessA(options.target, command_line, NULL, NULL, FALSE,
                        DEBUG_ONLY_THIS_PROCESS, NULL, options.cwd, &startup, &process)) {
        fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
        return 4;
    }
    process_handle = process.hProcess;
    initial_thread_handle = process.hThread;
    write_receipt(&options, "RUNNING", "launch", "waiting-for-mode-registration");
    while (running) {
        if (!WaitForDebugEvent(&event, 100)) {
            if (GetLastError() != ERROR_SEM_TIMEOUT) {
                write_receipt(&options, "FAIL", "debugger", "wait-failed");
                fatal_failure = TRUE;
                break;
            }
            continue;
        }
        {
            BOOL confirmation_pending = FALSE;
            continue_status = DBG_CONTINUE;
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            close_create_process_handles(&event.u.CreateProcessInfo);
            if (!verify_signature(MIEL_MODE_CHANGE_ADDRESS, MIEL_MODE_CHANGE_SIGNATURE,
                                  sizeof(MIEL_MODE_CHANGE_SIGNATURE)) ||
                !verify_signature(requested_scene->constructor, requested_scene->constructor_signature,
                                  requested_scene->constructor_signature_size) ||
                !arm_breakpoint(
                    &registration_breakpoint, BP_REGISTRATION,
                    requested_scene->constructor, 2)) {
                write_receipt(&options, "FAIL", "preflight", "signature-or-breakpoint-failed");
                fatal_failure = TRUE;
                running = FALSE;
            }
        } else if (event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
            close_create_thread_handle(&event.u.CreateThread);
        } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
        } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            if (event.u.ExitProcess.dwExitCode != ERROR_SUCCESS) {
                write_receipt(&options, "FAIL", "process-exit", "nonzero-exit");
                confirmed = FALSE;
                fatal_failure = TRUE;
            } else if (!confirmed || loader_action_pending()) {
                write_receipt(&options, "FAIL", "process-exit", "scene-not-confirmed");
                fatal_failure = TRUE;
            }
            running = FALSE;
        } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = event.u.Exception.ExceptionRecord.ExceptionCode;
            DWORD reported_exception_address = (DWORD)(ULONG_PTR)
                event.u.Exception.ExceptionRecord.ExceptionAddress;
            BOOL handled = FALSE;
            if (code == trap_exception_code()) {
                HANDLE thread = OpenThread(THREAD_GET_CONTEXT, FALSE, event.dwThreadId);
                CONTEXT context;
                BOOL first_hit = FALSE, matched = FALSE, operation_ok = TRUE;
                memset(&context, 0, sizeof(context));
                context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                if (thread && GetThreadContext(thread, &context)) {
                    if (consume_breakpoint(
                            &registration_breakpoint, &context,
                            reported_exception_address, &first_hit)) {
                        matched = TRUE;
                        if (first_hit) {
                            operation_ok = arm_breakpoint(
                                &mode_breakpoint, BP_MODE_CHANGE,
                                MIEL_MODE_CHANGE_ADDRESS, 3);
                            if (operation_ok) write_receipt(&options, "RUNNING", "registered", "waiting-for-mode-transition");
                        }
                    } else if (consume_breakpoint(
                                   &mode_breakpoint, &context,
                                   reported_exception_address, &first_hit)) {
                        matched = TRUE;
                        if (first_hit) {
                            DWORD argument_address = context.Esp + 4;
                            mode_manager = context.Ecx;
                            request_sequence++;
                            operation_ok = write_exact(
                                argument_address, &requested_scene->mode_address, 4) &&
                                arm_scene_loader();
                            if (operation_ok) write_receipt(&options, "RUNNING", "mode-transition", "target-substituted");
                        }
                    } else if (consume_loader_breakpoint(
                                   &context, reported_exception_address,
                                   &first_hit)) {
                        matched = TRUE;
                        /* Keep the scene thread parked after Continue while
                         * the remote loader runs on an otherwise live process.
                         * This avoids suspending a thread that owns the loader
                         * lock before LoadLibrary has completed. */
                        if (first_hit && options.observer)
                            operation_ok = suspend_one_thread(event.dwThreadId);
                        if (first_hit && operation_ok) confirmation_pending = TRUE;
                    }
                    if (matched) {
                        handled = operation_ok;
                        if (!handled) {
                            write_receipt(&options, "FAIL", "debugger", "breakpoint-action-failed");
                            fatal_failure = TRUE;
                            running = FALSE;
                        }
                    }
                }
                if (thread) CloseHandle(thread);
            }
            /* Wine raises its own startup INT3 even when scene traps use UD2. */
            if (!handled && code == EXCEPTION_BREAKPOINT &&
                event.u.Exception.dwFirstChance && !initial_breakpoint_seen) {
                initial_breakpoint_seen = TRUE;
                continue_status = DBG_CONTINUE;
            } else if (!handled) {
                continue_status = DBG_EXCEPTION_NOT_HANDLED;
                if (!event.u.Exception.dwFirstChance) {
                    write_receipt(&options, "FAIL", "debugger",
                                  "unhandled-second-chance-exception");
                    confirmed = FALSE;
                    fatal_failure = TRUE;
                    running = FALSE;
                }
            }
        }
        if (!continue_debug_event_checked(&options, &event, continue_status)) {
            confirmed = FALSE;
            fatal_failure = TRUE;
            running = FALSE;
        } else if (confirmation_pending && running) {
            confirmed = TRUE;
            if (options.observer) {
                LPVOID remote_path = NULL;
                DWORD observer_module = 0;
                HANDLE observer_thread = begin_observer_injection(
                    event.dwProcessId, options.observer, &remote_path);
                BOOL detached = observer_thread && DebugSetProcessKillOnExit(FALSE) &&
                    DebugActiveProcessStop(event.dwProcessId);
                BOOL loaded = detached && finish_observer_load(
                    observer_thread, remote_path, &observer_module);
                BOOL suspended = loaded && suspend_process_threads(
                    event.dwProcessId, event.dwThreadId);
                BOOL injected = suspended && initialize_observer(
                    observer_module, options.observer);
                if (!detached && observer_thread) {
                    TerminateProcess(process_handle, 5);
                    CloseHandle(observer_thread);
                }
                BOOL resumed = FALSE;
                if (loaded && suspended && injected)
                    resumed = resume_process_threads();
                if (!loaded || !suspended || !injected || !resumed) {
                    write_receipt(&options, "FAIL", "observer", "injection-failed");
                    confirmed = FALSE;
                    fatal_failure = TRUE;
                    TerminateProcess(process_handle, 5);
                    close_suspended_thread_handles();
                } else {
                    write_receipt(&options, "PASS", "scene-loader", "target-confirmed-observer-loaded");
                }
                if (options.quit_on_confirm) TerminateProcess(process_handle, 0);
                running = FALSE;
            } else {
                write_receipt(&options, "PASS", "scene-loader", "target-confirmed");
            }
        }
        }
        if (!running) break;
        if (confirmed && options.quit_on_confirm) {
            if (!TerminateProcess(process_handle, 0)) {
                write_receipt(&options, "FAIL", "debugger", "terminate-failed");
                confirmed = FALSE;
                fatal_failure = TRUE;
            }
            running = FALSE;
        }
    }
    if (initial_thread_handle) CloseHandle(initial_thread_handle);
    close_suspended_thread_handles();
    CloseHandle(process_handle);
    return confirmed && !fatal_failure ? 0 : 5;
}
