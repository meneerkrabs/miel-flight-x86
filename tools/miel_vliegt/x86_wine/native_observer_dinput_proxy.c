#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef HRESULT (WINAPI *DirectInputCreateAFunction)(
    HINSTANCE, DWORD, void **, void *);
typedef DWORD (WINAPI *MielObserverInitializeFunction)(LPVOID);

#define BOOTSTRAP_TIMEOUT_MS 600000u

static HMODULE real_dinput;
static DirectInputCreateAFunction real_direct_input_create;
static volatile LONG initialization_state;

static void proxy_diagnostic(const char *reason)
{
    char line[160];
    int length = snprintf(line, sizeof(line), "MVP %s\n", reason);
    if (length > 0 && (size_t)length < sizeof(line)) OutputDebugStringA(line);
}

static void signal_observer_failure(void)
{
    char event_name[96];
    fprintf(stderr, "MVP_signal_failure: signaling observer failure\n"); fflush(stderr);
    HANDLE failure_event;
    int length = snprintf(
        event_name,
        sizeof(event_name),
        "Local\\MielObserverFailure-%lu",
        (unsigned long)GetCurrentProcessId());
    if (length <= 0 || (size_t)length >= sizeof(event_name)) return;
    failure_event = CreateEventA(NULL, TRUE, FALSE, event_name);
    if (!failure_event) return;
    SetEvent(failure_event);
    CloseHandle(failure_event);
}

static BOOL initialize_proxy(void)
{
    char dinput_path[MAX_PATH * 2];
    fprintf(stderr, "MVP_init: called\n"); fflush(stderr);
    char observer_path[MAX_PATH * 2];
    HMODULE observer_module;
    MielObserverInitializeFunction observer_initialize;
    DWORD length;
    const char *failure_reason = "initialize_unknown";
    LONG observed = InterlockedCompareExchange(&initialization_state, 1, 0);
    if (observed != 0) {
        while ((observed = InterlockedCompareExchange(
                    &initialization_state, 0, 0)) == 1) Sleep(1u);
        return observed == 2;
    }
    length = GetEnvironmentVariableA(
        "MIEL_REAL_DINPUT", dinput_path, sizeof(dinput_path));
    failure_reason = "real_dinput_environment";
    if (length == 0u || length >= sizeof(dinput_path)) goto failed;
    real_dinput = LoadLibraryA(dinput_path);
    failure_reason = "real_dinput_load";
    if (!real_dinput) goto failed;
    real_direct_input_create = (DirectInputCreateAFunction)(ULONG_PTR)
        GetProcAddress(real_dinput, "DirectInputCreateA");
    failure_reason = "real_dinput_export";
    if (!real_direct_input_create) goto failed;
    /* Cc.dll may not be loaded yet on first call. Don't signal failure -
       just return FALSE. The bootstrap thread and DirectInputCreateA will
       retry when Cc.dll becomes available. */
    if (!GetModuleHandleA("Cc.dll")) {
        InterlockedExchange(&initialization_state, 0);
        return FALSE;
    }
    length = GetEnvironmentVariableA(
        "MIEL_OBSERVER_DLL", observer_path, sizeof(observer_path));
    failure_reason = "observer_environment";
    if (length == 0u || length >= sizeof(observer_path)) goto failed;
    observer_module = LoadLibraryA(observer_path);
    failure_reason = "observer_load";
    if (!observer_module) goto failed;
    observer_initialize = (MielObserverInitializeFunction)(ULONG_PTR)
        GetProcAddress(observer_module, "MielObserverInitialize");
    if (!observer_initialize) {
        observer_initialize = (MielObserverInitializeFunction)(ULONG_PTR)
            GetProcAddress(observer_module, "MielObserverInitialize@4");
    }
    failure_reason = "observer_initialize";
    if (!observer_initialize || observer_initialize(NULL) != 1u) goto failed;
    proxy_diagnostic("observer_initialized");
    InterlockedExchange(&initialization_state, 2);
    return TRUE;
failed:
    proxy_diagnostic(failure_reason);
    signal_observer_failure();
    InterlockedExchange(&initialization_state, 3);
    return FALSE;
}

static DWORD WINAPI bootstrap_after_loader(LPVOID unused)
{
    DWORD started = GetTickCount();
    (void)unused;
    for (;;) {
        if (GetModuleHandleA("Cc.dll")) {
            proxy_diagnostic("cc_ready_initialize");
            return initialize_proxy() ? 0u : 1u;
        }
        if ((DWORD)(GetTickCount() - started) >= BOOTSTRAP_TIMEOUT_MS) {
            proxy_diagnostic("cc_ready_timeout");
            break;
        }
        Sleep(1u);
    }
    signal_observer_failure();
    InterlockedExchange(&initialization_state, 3);
    return 1u;
}

__declspec(dllexport) HRESULT WINAPI DirectInputCreateA(
    HINSTANCE instance, DWORD version, void **direct_input, void *outer)
{
    /* Try to initialize the observer proxy. If it fails (e.g. Cc.dll not
       loaded yet), still forward to the real DirectInputCreateA so the game
       doesn't crash. The bootstrap thread will retry observer initialization. */
    initialize_proxy();
    if (real_direct_input_create)
        return real_direct_input_create(instance, version, direct_input, outer);
    return (HRESULT)0x80004005L;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    HANDLE worker;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        fprintf(stderr, "MVP_DllMain: DINPUT proxy loaded\n"); fflush(stderr);
        DisableThreadLibraryCalls(instance);
        /* The thread begins after DLL attachment leaves loader lock, waits
           only for Cc.dll, and installs the observer before the fleeting
           pending-login transition. The observer itself proves that boundary. */
        worker = CreateThread(
            NULL, 0u, bootstrap_after_loader, NULL, 0u, NULL);
        if (!worker) {
            signal_observer_failure();
            InterlockedExchange(&initialization_state, 3);
        } else {
            CloseHandle(worker);
        }
    }
    return TRUE;
}

/* === Exit prevention: hook PostQuitMessage + ExitProcess === */
static void (WINAPI *real_ExitProcess)(UINT uExitCode) = NULL;

void WINAPI ExitProcess_hook(UINT uExitCode) {
    fprintf(stderr, "MVP_ExitProcess(%u): BLOCKED — running message pump\n", uExitCode);
    fflush(stderr);
    /* Instead of exiting, run a message pump to keep the game window alive.
       This allows the observer hook's threads to continue working. */
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    /* If we get here, WM_QUIT was received — still don't call real ExitProcess */
    fprintf(stderr, "MVP: message pump ended, sleeping forever\n"); fflush(stderr);
    Sleep(INFINITE);
}

/* VEH: log all exceptions to understand why the game exits */
LONG WINAPI crash_logger(PEXCEPTION_POINTERS ep) {
    if (ep && ep->ExceptionRecord) {
        DWORD code = ep->ExceptionRecord->ExceptionCode;
        /* Filter out common non-fatal exceptions */
        if (code != 0xE06D7363 &&  /* C++ exception */
            code != 0x406D1388 &&  /* SetThreadName */
            code != STATUS_BREAKPOINT &&
            code != STATUS_SINGLE_STEP) {
            fprintf(stderr, "MVP_EXC: code=0x%08X addr=%p\n",
                    code, ep->ExceptionRecord->ExceptionAddress);
            fflush(stderr);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void install_exit_hook(void) {
    /* Install VEH first to catch crashes */
    AddVectoredExceptionHandler(0, crash_logger);
    fprintf(stderr, "MVP: VEH crash logger installed\n"); fflush(stderr);
    
    /* Original inline hook code follows */
    {
    /* Inline hook: overwrite first 5 bytes of ExitProcess in kernel32
       with a JMP to our hook. This catches ALL calls to ExitProcess
       regardless of which module makes the call (game exe, MSVCRT, etc.). */
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) return;
    FARPROC target = GetProcAddress(kernel32, "ExitProcess");
    if (!target) return;
    
    /* x86 JMP rel32: E9 xx xx xx xx (5 bytes) */
    BYTE *code = (BYTE*)target;
    DWORD old_protect;
    if (!VirtualProtect(code, 5, PAGE_EXECUTE_READWRITE, &old_protect)) return;
    
    /* Calculate relative offset: hook - (target + 5) */
    LONG_PTR offset = (LONG_PTR)ExitProcess_hook - (LONG_PTR)(code + 5);
    code[0] = 0xE9;  /* JMP rel32 */
    *(LONG_PTR*)(code + 1) = offset;
    
    VirtualProtect(code, 5, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), code, 5);
    
    fprintf(stderr, "MVP: ExitProcess inline hook installed at %p -> %p\n",
            target, ExitProcess_hook);
    fflush(stderr);
    }
}
