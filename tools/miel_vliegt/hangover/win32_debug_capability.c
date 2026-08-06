#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define DEFAULT_DEADLINE_MS 10000
#define MAX_DEADLINE_MS 60000
#define MAX_EVENT_CODES 256
#define MAX_EXCEPTIONS 64
#define READY_SENTINEL "MIEL_HANGOVER_DEBUG_CAPABILITY_READY"
#define FIRST_EXECUTION_SENTINEL 0x13572451UL
#define SECOND_EXECUTION_SENTINEL 0x246813a2UL

typedef struct ProbeResult {
    BOOL create_process_returned;
    DWORD create_process_error;
    DWORD process_id;
    DWORD thread_id;
    BOOL create_process_event_seen;
    BOOL ready_debug_string_seen;
    BOOL deliberate_trap_arm_ok;
    BOOL deliberate_breakpoint_seen;
    DWORD deliberate_breakpoint_hits;
    BOOL deliberate_second_breakpoint_seen;
    BOOL deliberate_trap_restore_ok;
    BOOL deliberate_second_trap_restore_ok;
    BOOL restored_execution_semantics_ok;
    BOOL deliberate_trap_location_matches;
    DWORD deliberate_trap_address;
    DWORD deliberate_second_trap_address;
    DWORD deliberate_exception_address;
    DWORD deliberate_context_eip;
    BOOL startup_breakpoint_seen;
    BOOL startup_breakpoint_context_ok;
    BOOL get_thread_context_ok;
    BOOL set_thread_context_ok;
    BOOL context_mutation_roundtrip_ok;
    BOOL trap_resume_context_ok;
    BOOL remote_memory_roundtrip_ok;
    BOOL code_memory_roundtrip_ok;
    BOOL continue_attempted;
    BOOL continue_debug_event_ok;
    BOOL exit_process_seen;
    BOOL child_signaled;
    DWORD child_exit_code;
    DWORD wait_calls;
    DWORD last_wait_error;
    DWORD elapsed_ms;
    DWORD event_count;
    DWORD stored_event_count;
    DWORD event_codes[MAX_EVENT_CODES];
    DWORD exception_count;
    DWORD stored_exception_count;
    DWORD exception_codes[MAX_EXCEPTIONS];
    DWORD exception_addresses[MAX_EXCEPTIONS];
    DWORD exception_first_chance[MAX_EXCEPTIONS];
    const char *detail;
} ProbeResult;

static const char *json_bool(BOOL value)
{
    return value ? "true" : "false";
}

static DWORD __attribute__((naked, noinline)) deliberate_trap_site_one(void)
{
    __asm__ __volatile__("mov $0x13572451, %eax\n\tret");
}

static DWORD __attribute__((naked, noinline)) deliberate_trap_site_two(void)
{
    __asm__ __volatile__("mov $0x246813a2, %eax\n\tret");
}

static SIZE_T selected_trap_bytes(const char *trap_strategy, const BYTE **trap)
{
    static const BYTE int3[] = {0xcc};
    static const BYTE ud2[] = {0x0f, 0x0b};
    if (!strcmp(trap_strategy, "ud2")) {
        *trap = ud2;
        return sizeof(ud2);
    }
    *trap = int3;
    return sizeof(int3);
}

static BOOL write_receipt(const char *path, const ProbeResult *result, BOOL supported,
                          DWORD deadline_ms, const char *trap_strategy,
                          const char *run_nonce, const char *capture_binding_sha256)
{
    FILE *stream;
    BOOL write_ok;
    DWORD index;

    stream = fopen(path, "wb");
    if (!stream) return FALSE;

    fprintf(stream,
            "{\"schema\":1,\"protocol\":\"miel-hangover-win32-debug-capability\","
            "\"status\":\"%s\",\"phase\":\"debug-api-capability\","
            "\"detail\":\"%s\",\"debug_api_capability\":\"%s\","
            "\"trap_strategy\":\"%s\","
            "\"run_nonce\":\"%s\",\"capture_binding_sha256\":\"%s\","
            "\"controller_machine\":\"i386\",\"child_machine\":\"i386\","
            "\"deadline_ms\":%lu,\"elapsed_ms\":%lu,"
            "\"create_process\":{\"returned\":%s,\"error\":%lu,\"pid\":%lu,\"tid\":%lu},"
            "\"checks\":{\"create_process_event_seen\":%s,"
            "\"ready_debug_string_seen\":%s,\"deliberate_trap_arm_ok\":%s,"
            "\"deliberate_breakpoint_seen\":%s,"
            "\"deliberate_second_breakpoint_seen\":%s,"
            "\"deliberate_trap_restore_ok\":%s,"
            "\"deliberate_second_trap_restore_ok\":%s,"
            "\"restored_execution_semantics_ok\":%s,"
            "\"deliberate_trap_location_matches\":%s,"
            "\"startup_breakpoint_context_ok\":%s,"
            "\"get_thread_context_ok\":%s,\"set_thread_context_ok\":%s," 
            "\"context_mutation_roundtrip_ok\":%s," 
            "\"trap_resume_context_ok\":%s,"
            "\"remote_memory_roundtrip_ok\":%s,\"code_memory_roundtrip_ok\":%s," 
            "\"continue_attempted\":%s," 
            "\"continue_debug_event_ok\":%s,\"exit_process_seen\":%s},"
            "\"deliberate_trap_address\":%lu,"
            "\"deliberate_second_trap_address\":%lu,"
            "\"deliberate_exception_address\":%lu,"
            "\"deliberate_context_eip\":%lu,"
            "\"deliberate_breakpoint_hits\":%lu,"
            "\"startup_breakpoint_seen\":%s,"
            "\"wait_calls\":%lu,\"last_wait_error\":%lu,"
            "\"child_signaled\":%s,\"child_exit_code\":%lu,"
            "\"event_count\":%lu,\"events_truncated\":%s,\"event_codes\":[",
            supported ? "PASS" : "FAIL", result->detail,
            supported ? "SUPPORTED" : "UNSUPPORTED",
            trap_strategy,
            run_nonce, capture_binding_sha256,
            (unsigned long)deadline_ms, (unsigned long)result->elapsed_ms,
            json_bool(result->create_process_returned),
            (unsigned long)result->create_process_error,
            (unsigned long)result->process_id, (unsigned long)result->thread_id,
            json_bool(result->create_process_event_seen),
            json_bool(result->ready_debug_string_seen),
            json_bool(result->deliberate_trap_arm_ok),
            json_bool(result->deliberate_breakpoint_seen),
            json_bool(result->deliberate_second_breakpoint_seen),
            json_bool(result->deliberate_trap_restore_ok),
            json_bool(result->deliberate_second_trap_restore_ok),
            json_bool(result->restored_execution_semantics_ok),
            json_bool(result->deliberate_trap_location_matches),
            json_bool(result->startup_breakpoint_context_ok),
            json_bool(result->get_thread_context_ok),
            json_bool(result->set_thread_context_ok),
            json_bool(result->context_mutation_roundtrip_ok),
            json_bool(result->trap_resume_context_ok),
            json_bool(result->remote_memory_roundtrip_ok),
            json_bool(result->code_memory_roundtrip_ok),
            json_bool(result->continue_attempted),
            json_bool(result->continue_debug_event_ok),
            json_bool(result->exit_process_seen),
            (unsigned long)result->deliberate_trap_address,
            (unsigned long)result->deliberate_second_trap_address,
            (unsigned long)result->deliberate_exception_address,
            (unsigned long)result->deliberate_context_eip,
            (unsigned long)result->deliberate_breakpoint_hits,
            json_bool(result->startup_breakpoint_seen),
            (unsigned long)result->wait_calls, (unsigned long)result->last_wait_error,
            json_bool(result->child_signaled), (unsigned long)result->child_exit_code,
            (unsigned long)result->event_count,
            json_bool(result->event_count > result->stored_event_count));

    for (index = 0; index < result->stored_event_count; ++index)
        fprintf(stream, "%s%lu", index ? "," : "", (unsigned long)result->event_codes[index]);
    fprintf(stream, "],\"exception_count\":%lu,\"exceptions_truncated\":%s,\"exceptions\":[",
            (unsigned long)result->exception_count,
            json_bool(result->exception_count > result->stored_exception_count));
    for (index = 0; index < result->stored_exception_count; ++index)
        fprintf(stream, "%s{\"code\":%lu,\"address\":%lu,\"first_chance\":%lu}",
                index ? "," : "",
                (unsigned long)result->exception_codes[index],
                (unsigned long)result->exception_addresses[index],
                (unsigned long)result->exception_first_chance[index]);
    fputs("]}\n", stream);

    write_ok = !ferror(stream);
    if (fclose(stream)) write_ok = FALSE;
    return write_ok;
}

static BOOL remote_memory_roundtrip(HANDLE process)
{
    static const BYTE expected[] = {0x4d, 0x49, 0x45, 0x4c, 0x44, 0x42, 0x47, 0x01};
    BYTE actual[sizeof(expected)];
    SIZE_T written = 0, read = 0;
    void *remote;
    BOOL ok;

    remote = VirtualAllocEx(process, NULL, sizeof(expected), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return FALSE;
    memset(actual, 0, sizeof(actual));
    ok = WriteProcessMemory(process, remote, expected, sizeof(expected), &written) &&
         written == sizeof(expected) &&
         ReadProcessMemory(process, remote, actual, sizeof(actual), &read) &&
         read == sizeof(actual) && !memcmp(expected, actual, sizeof(expected));
    if (!VirtualFreeEx(process, remote, 0, MEM_RELEASE)) ok = FALSE;
    return ok;
}

static BOOL code_memory_roundtrip(HANDLE process, const void *address, const char *trap_strategy)
{
    BYTE original[2] = {0}, observed[2] = {0};
    const BYTE *trap;
    SIZE_T trap_size = selected_trap_bytes(trap_strategy, &trap);
    SIZE_T transferred = 0;
    BOOL wrote_trap = FALSE, restored = FALSE, ok = FALSE;

    if (!address ||
        !ReadProcessMemory(process, address, original, trap_size, &transferred) ||
        transferred != trap_size)
        return FALSE;
    transferred = 0;
    wrote_trap = WriteProcessMemory(process, (void *)address, trap, trap_size, &transferred) &&
        transferred == trap_size && FlushInstructionCache(process, address, trap_size);
    if (wrote_trap) {
        transferred = 0;
        ok = ReadProcessMemory(process, address, observed, trap_size, &transferred) &&
            transferred == trap_size && !memcmp(observed, trap, trap_size);
    }
    transferred = 0;
    restored = WriteProcessMemory(process, (void *)address, original, trap_size, &transferred) &&
        transferred == trap_size && FlushInstructionCache(process, address, trap_size);
    if (restored) {
        transferred = 0;
        restored = ReadProcessMemory(process, address, observed, trap_size, &transferred) &&
            transferred == trap_size && !memcmp(observed, original, trap_size);
    }
    return wrote_trap && ok && restored;
}

static BOOL arm_deliberate_trap(HANDLE process, DWORD address, const char *trap_strategy,
                                const BYTE expected[2], BYTE original[2])
{
    const BYTE *trap;
    SIZE_T transferred = 0;
    SIZE_T trap_size = selected_trap_bytes(trap_strategy, &trap);

    return address &&
        ReadProcessMemory(process, (const void *)(ULONG_PTR)address, original,
                          trap_size, &transferred) &&
        transferred == trap_size && !memcmp(original, expected, trap_size) &&
        WriteProcessMemory(process, (void *)(ULONG_PTR)address, trap,
                           trap_size, &transferred) &&
        transferred == trap_size &&
        FlushInstructionCache(process, (const void *)(ULONG_PTR)address, trap_size);
}

static BOOL restore_deliberate_trap(HANDLE process, DWORD address,
                                    const char *trap_strategy,
                                    const BYTE original[2])
{
    BYTE observed[2] = {0};
    const BYTE *unused;
    SIZE_T transferred = 0;
    SIZE_T trap_size = selected_trap_bytes(trap_strategy, &unused);

    return WriteProcessMemory(process, (void *)(ULONG_PTR)address, original,
                              trap_size, &transferred) &&
        transferred == trap_size &&
        FlushInstructionCache(process, (const void *)(ULONG_PTR)address, trap_size) &&
        ReadProcessMemory(process, (const void *)(ULONG_PTR)address, observed,
                          trap_size, &transferred) &&
        transferred == trap_size && !memcmp(observed, original, trap_size);
}

static BOOL read_ready_debug_string(HANDLE process, const OUTPUT_DEBUG_STRING_INFO *info,
                                    DWORD trap_addresses[2])
{
    char buffer[sizeof(READY_SENTINEL) + 32], *end;
    unsigned long first, second;
    SIZE_T prefix_size = strlen(READY_SENTINEL);
    SIZE_T requested, read = 0;

    if (info->fUnicode || !info->lpDebugStringData || !info->nDebugStringLength) return FALSE;
    requested = info->nDebugStringLength;
    if (requested >= sizeof(buffer)) requested = sizeof(buffer) - 1;
    if (!ReadProcessMemory(process, info->lpDebugStringData, buffer, requested, &read) || !read)
        return FALSE;
    buffer[read < sizeof(buffer) ? read : sizeof(buffer) - 1] = '\0';
    if (strncmp(buffer, READY_SENTINEL, prefix_size) || buffer[prefix_size] != ':') return FALSE;
    first = strtoul(buffer + prefix_size + 1, &end, 16);
    if (!first || *end != ':') return FALSE;
    second = strtoul(end + 1, &end, 16);
    if (!second || *end || first == second) return FALSE;
    trap_addresses[0] = (DWORD)first;
    trap_addresses[1] = (DWORD)second;
    return TRUE;
}

static BOOL read_thread_eip(DWORD thread_id, DWORD *eip)
{
    HANDLE thread;
    CONTEXT context;
    BOOL ok;

    thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_id);
    if (!thread) return FALSE;
    memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_CONTROL;
    ok = GetThreadContext(thread, &context);
    if (ok) *eip = context.Eip;
    CloseHandle(thread);
    return ok;
}

static BOOL normalize_startup_breakpoint_context(DWORD thread_id, DWORD exception_address)
{
    HANDLE thread;
    CONTEXT context;
    BOOL ok = FALSE;

    thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                        FALSE, thread_id);
    if (!thread) return FALSE;
    memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(thread, &context) &&
        (context.Eip == exception_address || context.Eip == exception_address + 1)) {
        /* SetThreadContext is required even when EIP is already normalized:
           FEX uses the roundtrip to synchronize its translated CPU/JIT state. */
        context.Eip = exception_address + 1;
        ok = SetThreadContext(thread, &context);
    }
    CloseHandle(thread);
    return ok;
}

static void probe_thread_context(DWORD thread_id, DWORD resume_eip, ProbeResult *result)
{
    HANDLE thread;
    CONTEXT original, mutated, observed, restored, resumed;

    result->get_thread_context_ok = FALSE;
    result->set_thread_context_ok = FALSE;
    result->context_mutation_roundtrip_ok = FALSE;
    result->trap_resume_context_ok = FALSE;
    thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                        FALSE, thread_id);
    if (!thread) return;
    memset(&original, 0, sizeof(original));
    original.ContextFlags = CONTEXT_FULL;
    result->get_thread_context_ok = GetThreadContext(thread, &original);
    if (result->get_thread_context_ok) {
        mutated = original;
        mutated.Eax ^= 0xa5a55a5aUL;
        if (mutated.Eax == original.Eax) mutated.Eax ^= 1;
        result->set_thread_context_ok = SetThreadContext(thread, &mutated);
        memset(&observed, 0, sizeof(observed));
        observed.ContextFlags = CONTEXT_FULL;
        if (result->set_thread_context_ok && GetThreadContext(thread, &observed) &&
            observed.Eax == mutated.Eax && SetThreadContext(thread, &original)) {
            memset(&restored, 0, sizeof(restored));
            restored.ContextFlags = CONTEXT_FULL;
            result->context_mutation_roundtrip_ok =
                GetThreadContext(thread, &restored) && restored.Eax == original.Eax;
            if (result->context_mutation_roundtrip_ok) {
                restored.Eip = resume_eip;
                memset(&resumed, 0, sizeof(resumed));
                resumed.ContextFlags = CONTEXT_FULL;
                result->trap_resume_context_ok =
                    SetThreadContext(thread, &restored) &&
                    GetThreadContext(thread, &resumed) &&
                    resumed.Eip == resume_eip && resumed.Eax == original.Eax;
            }
        }
    }
    CloseHandle(thread);
}

static void record_event(ProbeResult *result, DWORD code)
{
    if (result->stored_event_count < MAX_EVENT_CODES)
        result->event_codes[result->stored_event_count++] = code;
    result->event_count++;
}

static void record_exception(ProbeResult *result, const EXCEPTION_DEBUG_INFO *exception)
{
    if (result->stored_exception_count < MAX_EXCEPTIONS) {
        DWORD index = result->stored_exception_count++;
        result->exception_codes[index] = exception->ExceptionRecord.ExceptionCode;
        result->exception_addresses[index] =
            (DWORD)(ULONG_PTR)exception->ExceptionRecord.ExceptionAddress;
        result->exception_first_chance[index] = exception->dwFirstChance;
    }
    result->exception_count++;
}

static const char *deadline_detail(const ProbeResult *result)
{
    if (!result->create_process_event_seen) return "create-process-event-timeout";
    if (!result->ready_debug_string_seen) return "ready-debug-string-timeout";
    if (!result->deliberate_breakpoint_seen) return "deliberate-breakpoint-timeout";
    if (!result->deliberate_second_breakpoint_seen) return "second-breakpoint-timeout";
    return "exit-process-event-timeout";
}

static int run_parent(const char *receipt, DWORD deadline_ms, const char *trap_strategy,
                      const char *run_nonce, const char *capture_binding_sha256)
{
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    ProbeResult result;
    BYTE deliberate_original[2][2] = {{0}};
    static const BYTE deliberate_expected[2][2] = {{0xb8, 0x51}, {0xb8, 0xa2}};
    char executable[MAX_PATH];
    char command_line[MAX_PATH + 64];
    DWORD deliberate_trap_addresses[2] = {0}, deliberate_seen_mask = 0;
    DWORD executable_length, started, wait_ms;
    BOOL running = TRUE, supported;

    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    memset(&result, 0, sizeof(result));
    startup.cb = sizeof(startup);
    result.startup_breakpoint_context_ok = TRUE;
    result.continue_debug_event_ok = TRUE;
    result.child_exit_code = STILL_ACTIVE;

    executable_length = GetModuleFileNameA(NULL, executable, sizeof(executable));
    if (!executable_length || executable_length >= sizeof(executable) ||
        strlen(executable) + strlen(trap_strategy) + sizeof("\"\" --child --trap ") > sizeof(command_line)) {
        result.detail = "self-path-unavailable";
        if (!write_receipt(receipt, &result, FALSE, deadline_ms, trap_strategy,
                           run_nonce, capture_binding_sha256)) return 3;
        return 1;
    }
    snprintf(command_line, sizeof(command_line), "\"%s\" --child --trap %s", executable, trap_strategy);

    started = GetTickCount();
    result.create_process_returned = CreateProcessA(
        executable, command_line, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS,
        NULL, NULL, &startup, &process);
    result.create_process_error = result.create_process_returned ? ERROR_SUCCESS : GetLastError();
    if (!result.create_process_returned) {
        result.elapsed_ms = GetTickCount() - started;
        result.detail = "create-process-failed";
        if (!write_receipt(receipt, &result, FALSE, deadline_ms, trap_strategy,
                           run_nonce, capture_binding_sha256)) return 3;
        return 1;
    }
    result.process_id = process.dwProcessId;
    result.thread_id = process.dwThreadId;

    while (running) {
        DEBUG_EVENT event;
        DWORD elapsed = GetTickCount() - started;
        DWORD continue_status = DBG_CONTINUE;
        BOOL continued;

        if (elapsed >= deadline_ms) {
            result.detail = deadline_detail(&result);
            break;
        }
        wait_ms = deadline_ms - elapsed;
        if (wait_ms > 100) wait_ms = 100;
        result.wait_calls++;
        if (!WaitForDebugEvent(&event, wait_ms)) {
            result.last_wait_error = GetLastError();
            if (result.last_wait_error != ERROR_SEM_TIMEOUT) {
                result.detail = "wait-for-debug-event-failed";
                break;
            }
            if (WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0)
                result.child_signaled = TRUE;
            continue;
        }

        result.last_wait_error = ERROR_SUCCESS;
        record_event(&result, event.dwDebugEventCode);
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            result.create_process_event_seen = TRUE;
            result.remote_memory_roundtrip_ok = remote_memory_roundtrip(process.hProcess);
            result.code_memory_roundtrip_ok = code_memory_roundtrip(
                process.hProcess, event.u.CreateProcessInfo.lpStartAddress, trap_strategy);
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
            if (event.u.CreateProcessInfo.hThread &&
                event.u.CreateProcessInfo.hThread != process.hThread)
                CloseHandle(event.u.CreateProcessInfo.hThread);
            if (event.u.CreateProcessInfo.hProcess &&
                event.u.CreateProcessInfo.hProcess != process.hProcess)
                CloseHandle(event.u.CreateProcessInfo.hProcess);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            if (event.u.CreateThread.hThread) CloseHandle(event.u.CreateThread.hThread);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            if (read_ready_debug_string(process.hProcess, &event.u.DebugString,
                                        deliberate_trap_addresses)) {
                result.ready_debug_string_seen = TRUE;
                result.deliberate_trap_address = deliberate_trap_addresses[0];
                result.deliberate_second_trap_address = deliberate_trap_addresses[1];
                result.deliberate_trap_arm_ok =
                    arm_deliberate_trap(process.hProcess, deliberate_trap_addresses[0],
                                        trap_strategy, deliberate_expected[0],
                                        deliberate_original[0]) &&
                    arm_deliberate_trap(process.hProcess, deliberate_trap_addresses[1],
                                        trap_strategy, deliberate_expected[1],
                                        deliberate_original[1]);
                if (!result.deliberate_trap_arm_ok) {
                    result.detail = "deliberate-trap-arm-failed";
                    running = FALSE;
                }
            }
            break;
        case EXCEPTION_DEBUG_EVENT:
        {
            DWORD code = event.u.Exception.ExceptionRecord.ExceptionCode;
            DWORD exception_address =
                (DWORD)(ULONG_PTR)event.u.Exception.ExceptionRecord.ExceptionAddress;
            BOOL first_chance = event.u.Exception.dwFirstChance != 0;
            BOOL owned = FALSE;
            record_exception(&result, &event.u.Exception);
            if (result.ready_debug_string_seen &&
                code == (!strcmp(trap_strategy, "ud2")
                    ? EXCEPTION_ILLEGAL_INSTRUCTION : EXCEPTION_BREAKPOINT)) {
                DWORD context_eip = 0;
                int trap_index = -1;
                unsigned index;
                read_thread_eip(event.dwThreadId, &context_eip);
                for (index = 0; index < 2; ++index) {
                    DWORD address = deliberate_trap_addresses[index];
                    if (exception_address == address || context_eip == address ||
                        (!strcmp(trap_strategy, "int3") &&
                         context_eip == address + 1)) {
                        trap_index = (int)index;
                        break;
                    }
                }
                if (trap_index >= 0 &&
                    !(deliberate_seen_mask & (1UL << trap_index))) {
                    BOOL restored = restore_deliberate_trap(
                        process.hProcess, deliberate_trap_addresses[trap_index],
                        trap_strategy, deliberate_original[trap_index]);
                    if (!result.deliberate_breakpoint_seen) {
                        result.deliberate_exception_address = exception_address;
                        result.deliberate_context_eip = context_eip;
                    }
                    result.deliberate_trap_location_matches = TRUE;
                    if (trap_index == 0) result.deliberate_trap_restore_ok = restored;
                    else result.deliberate_second_trap_restore_ok = restored;
                    if (restored)
                        probe_thread_context(
                            event.dwThreadId, deliberate_trap_addresses[trap_index], &result);
                    owned = restored && result.trap_resume_context_ok;
                    if (owned) {
                        deliberate_seen_mask |= 1UL << trap_index;
                        result.deliberate_breakpoint_hits++;
                        result.deliberate_breakpoint_seen = TRUE;
                        if (result.deliberate_breakpoint_hits >= 2) {
                            result.deliberate_second_breakpoint_seen = TRUE;
                        }
                    } else {
                        result.detail = "deliberate-trap-resume-failed";
                        running = FALSE;
                    }
                }
            } else if (first_chance && !result.ready_debug_string_seen &&
                       code == EXCEPTION_BREAKPOINT &&
                       !result.startup_breakpoint_seen) {
                result.startup_breakpoint_seen = TRUE;
                result.startup_breakpoint_context_ok = normalize_startup_breakpoint_context(
                    event.dwThreadId, exception_address);
                owned = result.startup_breakpoint_context_ok;
                if (!owned) {
                    result.detail = "startup-breakpoint-context-failed";
                    running = FALSE;
                }
            }
            if (!owned) {
                continue_status = DBG_EXCEPTION_NOT_HANDLED;
                if (!first_chance) {
                    result.detail = "unhandled-second-chance-exception";
                    running = FALSE;
                }
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            result.exit_process_seen = TRUE;
            result.child_signaled = TRUE;
            result.child_exit_code = event.u.ExitProcess.dwExitCode;
            result.restored_execution_semantics_ok =
                event.u.ExitProcess.dwExitCode == ERROR_SUCCESS;
            running = FALSE;
            break;
        default:
            break;
        }

        result.continue_attempted = TRUE;
        continued = ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status);
        if (!continued) {
            result.continue_debug_event_ok = FALSE;
            result.detail = "continue-debug-event-failed";
            break;
        }
    }

    if (!result.exit_process_seen &&
        WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0)
        result.child_signaled = TRUE;
    if (!result.exit_process_seen) {
        DWORD child_exit_code;
        if (GetExitCodeProcess(process.hProcess, &child_exit_code) && child_exit_code != STILL_ACTIVE) {
            result.child_exit_code = child_exit_code;
            result.child_signaled = TRUE;
        }
    }
    result.elapsed_ms = GetTickCount() - started;

    supported = result.create_process_event_seen && result.ready_debug_string_seen &&
        result.deliberate_trap_arm_ok && result.deliberate_breakpoint_seen &&
        result.deliberate_second_breakpoint_seen &&
        result.deliberate_trap_restore_ok && result.deliberate_second_trap_restore_ok &&
        result.restored_execution_semantics_ok &&
        result.deliberate_trap_location_matches &&
        result.get_thread_context_ok &&
        result.startup_breakpoint_context_ok &&
        result.set_thread_context_ok && result.context_mutation_roundtrip_ok &&
        result.trap_resume_context_ok &&
        result.remote_memory_roundtrip_ok && result.code_memory_roundtrip_ok &&
        result.continue_attempted && result.continue_debug_event_ok && result.exit_process_seen &&
        result.child_exit_code == ERROR_SUCCESS;
    if (!result.detail) {
        if (!result.create_process_event_seen) result.detail = "create-process-event-missing";
        else if (!result.remote_memory_roundtrip_ok) result.detail = "remote-memory-roundtrip-failed";
        else if (!result.ready_debug_string_seen) result.detail = "ready-debug-string-missing";
        else if (!result.deliberate_trap_arm_ok) result.detail = "deliberate-trap-arm-failed";
        else if (!result.deliberate_breakpoint_seen) result.detail = "deliberate-breakpoint-missing";
        else if (!result.deliberate_second_breakpoint_seen)
            result.detail = "second-deliberate-breakpoint-missing";
        else if (!result.deliberate_trap_restore_ok ||
                 !result.deliberate_second_trap_restore_ok)
            result.detail = "deliberate-trap-restore-failed";
        else if (!result.restored_execution_semantics_ok)
            result.detail = "restored-instruction-not-executed";
        else if (!result.deliberate_trap_location_matches)
            result.detail = "deliberate-trap-location-mismatch";
        else if (!result.startup_breakpoint_context_ok)
            result.detail = "startup-breakpoint-context-failed";
        else if (!result.get_thread_context_ok || !result.set_thread_context_ok)
            result.detail = "thread-context-roundtrip-failed";
        else if (!result.context_mutation_roundtrip_ok)
            result.detail = "thread-context-mutation-not-observed";
        else if (!result.trap_resume_context_ok)
            result.detail = "trap-resume-context-failed";
        else if (!result.code_memory_roundtrip_ok) result.detail = "code-memory-roundtrip-failed";
        else if (!result.exit_process_seen) result.detail = "exit-process-event-missing";
        else if (result.child_exit_code != ERROR_SUCCESS) result.detail = "child-exit-nonzero";
        else result.detail = "supported";
    }

    /* Publish the terminal verdict before cleanup. A broken debug backend can
       block TerminateProcess or handle teardown; the host watchdog may then
       kill this controller without losing the capability evidence. */
    if (!write_receipt(receipt, &result, supported, deadline_ms, trap_strategy,
                       run_nonce, capture_binding_sha256)) {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 3;
    }
    if (!result.exit_process_seen && !result.child_signaled)
        TerminateProcess(process.hProcess, 1);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return supported ? 0 : 1;
}

int main(int argc, char **argv)
{
    const char *receipt = NULL;
    const char *trap_strategy = "int3";
    const char *run_nonce = NULL;
    const char *capture_binding_sha256 = NULL;
    DWORD deadline_ms = DEFAULT_DEADLINE_MS;
    BOOL valid = TRUE;
    int index;

    if (argc == 4 && !strcmp(argv[1], "--child") &&
        !strcmp(argv[2], "--trap") &&
        (!strcmp(argv[3], "int3") || !strcmp(argv[3], "ud2"))) {
        char ready[sizeof(READY_SENTINEL) + 32];
        snprintf(ready, sizeof(ready), "%s:%08lx:%08lx", READY_SENTINEL,
                 (unsigned long)(ULONG_PTR)deliberate_trap_site_one,
                 (unsigned long)(ULONG_PTR)deliberate_trap_site_two);
        OutputDebugStringA(ready);
        return deliberate_trap_site_one() == FIRST_EXECUTION_SENTINEL &&
               deliberate_trap_site_two() == SECOND_EXECUTION_SENTINEL ? 0 : 9;
    }

    for (index = 1; index < argc; ++index) {
        if (!strcmp(argv[index], "--receipt") && index + 1 < argc) {
            receipt = argv[++index];
        } else if (!strcmp(argv[index], "--deadline-ms") && index + 1 < argc) {
            char *end;
            unsigned long value = strtoul(argv[++index], &end, 10);
            if (*end || !value || value > MAX_DEADLINE_MS) valid = FALSE;
            else deadline_ms = (DWORD)value;
        } else if (!strcmp(argv[index], "--trap") && index + 1 < argc) {
            trap_strategy = argv[++index];
            if (strcmp(trap_strategy, "int3") && strcmp(trap_strategy, "ud2")) valid = FALSE;
        } else if (!strcmp(argv[index], "--run-nonce") && index + 1 < argc) {
            run_nonce = argv[++index];
        } else if (!strcmp(argv[index], "--capture-binding-sha256") &&
                   index + 1 < argc) {
            capture_binding_sha256 = argv[++index];
        } else {
            valid = FALSE;
            break;
        }
    }
    if (!valid || !receipt || !run_nonce || !capture_binding_sha256 ||
        strlen(run_nonce) != 64 || strlen(capture_binding_sha256) != 64) {
        fputs("usage: win32-debug-capability --receipt FILE [--deadline-ms N] "
              "[--trap int3|ud2] --run-nonce HEX64 "
              "--capture-binding-sha256 HEX64\n", stderr);
        return 2;
    }
    for (index = 0; index < 64; ++index) {
        char nonce = run_nonce[index];
        char binding = capture_binding_sha256[index];
        if (!((nonce >= '0' && nonce <= '9') || (nonce >= 'a' && nonce <= 'f')) ||
            !((binding >= '0' && binding <= '9') ||
              (binding >= 'a' && binding <= 'f'))) {
            fputs("run nonce and capture binding must be lowercase hex\n", stderr);
            return 2;
        }
    }
    return run_parent(receipt, deadline_ms, trap_strategy, run_nonce,
                      capture_binding_sha256);
}
