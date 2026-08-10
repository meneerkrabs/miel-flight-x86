#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef LONG NTSTATUS;
#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef HRESULT (WINAPI *DirectInputCreateAFunction)(
    HINSTANCE, DWORD, void **, void *);
typedef DWORD (WINAPI *MielObserverInitializeFunction)(LPVOID);

#define BOOTSTRAP_TIMEOUT_MS 600000u

static HMODULE real_dinput;
static DirectInputCreateAFunction real_direct_input_create;
static volatile LONG initialization_state;

static void proxy_log_file(const char *msg)
{
    /* Write debug output to a file that survives in artifacts */
    HANDLE h = CreateFileA("proxy-debug.log", FILE_APPEND_DATA, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(h, msg, lstrlenA(msg), &written, NULL);
        WriteFile(h, "\r\n", 2, &written, NULL);
        CloseHandle(h);
    }
}

/* === GetVersionEx hook: lie about OS version for old games === */
typedef BOOL (WINAPI *GetVersionExA_t)(LPOSVERSIONINFOA);
static GetVersionExA_t real_GetVersionExA = NULL;

BOOL WINAPI GetVersionExA_hook(LPOSVERSIONINFOA lpVersionInformation) {
    BOOL result = real_GetVersionExA(lpVersionInformation);
    if (result && lpVersionInformation) {
        /* Report as Windows XP SP3 (5.1.2600) */
        lpVersionInformation->dwMajorVersion = 5;
        lpVersionInformation->dwMinorVersion = 1;
        lpVersionInformation->dwBuildNumber = 2600;
        lpVersionInformation->dwPlatformId = VER_PLATFORM_WIN32_NT;
    }
    return result;
}

static void install_exit_hook(void);

static void install_version_hook(void) {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) return;
    real_GetVersionExA = (GetVersionExA_t)GetProcAddress(kernel32, "GetVersionExA");
    if (!real_GetVersionExA) return;
    
    BYTE *target = (BYTE*)real_GetVersionExA;
    DWORD old_protect;
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old_protect)) return;
    
    LONG_PTR offset = (LONG_PTR)GetVersionExA_hook - (LONG_PTR)(target + 5);
    target[0] = 0xE9;
    *(LONG_PTR*)(target + 1) = offset;
    
    VirtualProtect(target, 5, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), target, 5);
    proxy_log_file("GetVersionExA hook installed (XP SP3)");
}

static void proxy_diagnostic(const char *reason)
{
    char line[160];
    int length = snprintf(line, sizeof(line), "MVP %s\n", reason);
    if (length > 0 && (size_t)length < sizeof(line)) OutputDebugStringA(line);
    /* Mirror to the proxy log file: OutputDebugStringA is invisible without a
       debugger (it only surfaces as a benign 0x40010006 DBG_PRINTEXCEPTION_C
       in the VEH logger), so the actual reason string — cc_ready_timeout,
       observer_environment, observer_load, observer_initialize,
       observer_initialized — was never recoverable from the artifact. */
    { char f[176]; int n = snprintf(f, sizeof(f), "DIAG %s", reason);
      if (n > 0 && (size_t)n < sizeof(f)) proxy_log_file(f); }
}

static void signal_observer_failure(void)
{
    char event_name[96];
    fprintf(stderr, "MVP_signal_failure: signaling observer failure\n"); fflush(stderr);
    proxy_log_file("SIGNAL observer failure");
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
    if (!observer_module) {
        /* LoadLibrary failed — capture WHY: GetLastError (126 =
           ERROR_MOD_NOT_FOUND missing dependency, 2 = file not found,
           193 = bad exe format) plus the path we tried, so the artifact
           names the cause instead of a bare observer_load. */
        char lb[MAX_PATH * 2 + 64];
        int ln = snprintf(lb, sizeof(lb), "observer_load FAILED err=%lu path=%s",
                          (unsigned long)GetLastError(), observer_path);
        if (ln > 0 && (size_t)ln < sizeof(lb)) proxy_log_file(lb);
        goto failed;
    }
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

/* === ddraw.dll!DirectDrawCreate diagnostic probe (fwd decls) ===
   The game loops IDirectDraw::SetDisplayMode(640x480)->DDERR_UNSUPPORTED
   headless. Before stubbing we need the COM interface version (IDirectDraw vs
   IDirectDraw2 vs IDirectDraw7) and the exact SetDisplayMode argcount. This
   probe hooks DirectDrawCreate with a TRAMPOLINE so the real fn still runs,
   then dumps the returned object's vtable + logs every QueryInterface riid. */
static BOOL ddraw_probe_installed = FALSE;
static void install_ddraw_hook(void);

static DWORD WINAPI bootstrap_after_loader(LPVOID unused)
{
    DWORD started = GetTickCount();
    BOOL initialized = FALSE;
    (void)unused;
    for (;;) {
        /* ddraw.dll loads during the game's display init, which happens AFTER
           Cc.dll. So keep polling for ddraw even past observer init, otherwise
           the probe never installs (the old loop returned on Cc.dll ready). */
        if (!ddraw_probe_installed && GetModuleHandleA("ddraw.dll")) {
            ddraw_probe_installed = TRUE;
            install_ddraw_hook();
        }
        if (!initialized && GetModuleHandleA("Cc.dll")) {
            proxy_diagnostic("cc_ready_initialize");
            if (!initialize_proxy()) return 1u;
            initialized = TRUE;
        }
        if (initialized && ddraw_probe_installed) return 0u;
        if ((DWORD)(GetTickCount() - started) >= BOOTSTRAP_TIMEOUT_MS) {
            if (initialized) return 0u;
            proxy_diagnostic("cc_ready_timeout");
            break;
        }
        Sleep(1u);
    }
    signal_observer_failure();
    InterlockedExchange(&initialization_state, 3);
    return 1u;
}

/* === DirectInput Acquire unblock ===
   The game's MAIN thread blocks headless inside dinput.dll during startup
   (stack-walk: parked in an ntdll wait with the call chain entirely in
   dinput.dll) — IDirectInputDevice::Acquire waits on a foreground/focused
   window that never exists headless, so the Manager never constructs. The
   suite injects input via SendInput, so a real device acquire isn't needed:
   stub Acquire (IDirectInputDevice vtable index 7, `this`-only = ret 0x4) to
   return DI_OK(0) immediately. Reached by wrapping IDirectInput::CreateDevice
   (vtable index 3) to patch each returned device's Acquire slot. */
static __attribute__((naked)) void di_acquire_stub(void)
{
    __asm__ __volatile__("xorl %eax, %eax\n\tret $0x4\n");
}

static void *di_createdevice_saved = NULL;

static void patch_device_acquire(void *dev)
{
    if (!dev || IsBadReadPtr(dev, sizeof(void *))) return;
    {
        void **vtbl = *(void ***)dev;
        DWORD op;
        if (!IsBadReadPtr(&vtbl[7], sizeof(void *)) && vtbl[7] != di_acquire_stub &&
            VirtualProtect(&vtbl[7], sizeof(void *), PAGE_READWRITE, &op)) {
            vtbl[7] = (void *)di_acquire_stub;
            VirtualProtect(&vtbl[7], sizeof(void *), op, &op);
            FlushInstructionCache(GetCurrentProcess(), &vtbl[7], sizeof(void *));
            proxy_log_file("MVP_DI Acquire patched -> DI_OK");
        }
    }
}

typedef HRESULT(WINAPI *CreateDevice_t)(void *thisptr, const void *rguid,
                                        void **lplpDev, void *outer);

static HRESULT WINAPI di_CreateDevice_hook(void *thisptr, const void *rguid,
                                           void **lplpDev, void *outer)
{
    HRESULT hr = ((CreateDevice_t)di_createdevice_saved)(thisptr, rguid,
                                                         lplpDev, outer);
    if (SUCCEEDED(hr) && lplpDev && *lplpDev) patch_device_acquire(*lplpDev);
    return hr;
}

/* Patch an IDirectInput object's CreateDevice slot (index 3) so every device
   it creates gets its Acquire stubbed. Shared vtable → patch once. */
static void patch_directinput_createdevice(void *di)
{
    if (di_createdevice_saved || !di || IsBadReadPtr(di, sizeof(void *))) return;
    {
        void **vtbl = *(void ***)di;
        DWORD op;
        if (!IsBadReadPtr(&vtbl[3], sizeof(void *))) {
            di_createdevice_saved = vtbl[3];
            if (VirtualProtect(&vtbl[3], sizeof(void *), PAGE_READWRITE, &op)) {
                vtbl[3] = (void *)di_CreateDevice_hook;
                VirtualProtect(&vtbl[3], sizeof(void *), op, &op);
                FlushInstructionCache(GetCurrentProcess(), &vtbl[3],
                                      sizeof(void *));
                proxy_log_file("MVP_DI CreateDevice hooked");
            } else {
                di_createdevice_saved = NULL;
            }
        }
    }
}

__declspec(dllexport) HRESULT WINAPI DirectInputCreateA(
    HINSTANCE instance, DWORD version, void **direct_input, void *outer)
{
    /* Try to initialize the observer proxy. If it fails (e.g. Cc.dll not
       loaded yet), still forward to the real DirectInputCreateA so the game
       doesn't crash. The bootstrap thread will retry observer initialization. */
    initialize_proxy();
    if (real_direct_input_create) {
        HRESULT hr = real_direct_input_create(instance, version, direct_input,
                                              outer);
        if (SUCCEEDED(hr) && direct_input && *direct_input) {
            patch_directinput_createdevice(*direct_input);
        }
        return hr;
    }
    return (HRESULT)0x80004005L;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    HANDLE worker;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        fprintf(stderr, "MVP_DllMain: DINPUT proxy loaded\n"); fflush(stderr);
    proxy_log_file("DllMain: DINPUT proxy loaded");
    /* Dump observer env vars for debugging */
    {
        const char *sc = getenv("MIEL_OBSERVER_SCENARIO");
        const char *sh = getenv("MIEL_OBSERVER_SCENARIO_SHA256");
        const char *lg = getenv("MIEL_OBSERVER_LOG");
        proxy_log_file("ENV_DUMP_START");
    { char _eb[1024]; wsprintfA(_eb, "ENV SCENARIO=%s SHA=%s LOG=%s", sc ? sc : "(null)", sh ? sh : "(null)", lg ? lg : "(null)"); proxy_log_file(_eb); }
    proxy_log_file("ENV_DUMP_END");
    fprintf(stderr, "MVP_ENV: SCENARIO=%s SHA=%s LOG=%s\n",
                sc ? sc : "(null)", sh ? sh : "(null)", lg ? lg : "(null)");
        fflush(stderr);
        if (sc) {
            FILE *tf = fopen(sc, "rb");
            if (tf) { fseek(tf, 0, SEEK_END); fprintf(stderr, "MVP_FILE: %s size=%ld OK\n", sc, ftell(tf)); fclose(tf); }
            else { fprintf(stderr, "MVP_FILE: %s CANNOT OPEN errno=%d\n", sc, errno); }
            fflush(stderr);
        }
    }
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
    { HMODULE _exe = GetModuleHandleA(NULL); HMODULE _cc = GetModuleHandleA("Cc.dll"); fprintf(stderr, "MVP_BASE: exe=%p cc=%p\n", _exe, _cc); fflush(stderr); }
    install_version_hook();
    /* install_exit_hook was defined but never called — the ExitProcess hook
       runnerattempt.md described was never live, and every self-exit ran
       unobserved. Install the exit/terminate hooks + VEH here. */
    install_exit_hook();
    return TRUE;
}

/* Resolve a code address to "module.dll+0xoffset" so the exit-caller is
   identifiable in the artifact without a debugger on the runner. */
static void describe_address(void *addr, char *out, size_t out_size) {
    HMODULE mod = NULL;
    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)addr, &mod) && mod) {
        char path[MAX_PATH];
        DWORD n = GetModuleFileNameA(mod, path, sizeof(path));
        const char *base = path;
        if (n) {
            for (DWORD i = 0; i < n; i++)
                if (path[i] == '\\' || path[i] == '/') base = path + i + 1;
        } else {
            base = "?";
        }
        wsprintfA(out, "%s+0x%X", base,
                  (unsigned)((BYTE *)addr - (BYTE *)mod));
    } else {
        wsprintfA(out, "0x%p (no module)", addr);
    }
    (void)out_size;
}

/* === Exit prevention: hook PostQuitMessage + ExitProcess === */
static void (WINAPI *real_ExitProcess)(UINT uExitCode) = NULL;

void WINAPI ExitProcess_hook(UINT uExitCode) {
    char who[MAX_PATH + 32];
    describe_address(__builtin_return_address(0), who, sizeof(who));
    { char b[MAX_PATH + 96];
      wsprintfA(b, "MVP_ExitProcess(%u) caller=%s BLOCKED", uExitCode, who);
      proxy_log_file(b);
      fprintf(stderr, "%s\n", b); fflush(stderr); }
    /* Don't exit — keep the process alive for the observer. */
    /* Sleep on this thread, let the game's other threads continue. */
    Sleep(INFINITE);
}

/* Saved original prologue bytes so a non-self call can pass through the real
   function without re-entering the hook (inline JMP patches have no
   trampoline). Low-frequency calls, so unhook/call/rehook under a lock is
   fine. */
static CRITICAL_SECTION passthrough_lock;
static BOOL passthrough_lock_ready = FALSE;
static BYTE saved_TerminateProcess[5];
static BYTE saved_NtTerminateProcess[5];

static void restore_bytes(void *target, const BYTE *saved) {
    DWORD op;
    if (VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &op)) {
        memcpy(target, saved, 5);
        VirtualProtect(target, 5, op, &op);
        FlushInstructionCache(GetCurrentProcess(), target, 5);
    }
}
static void rehook(void *target, void *hook) {
    DWORD op;
    if (VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &op)) {
        ((BYTE *)target)[0] = 0xE9;
        *(LONG_PTR *)((BYTE *)target + 1) =
            (LONG_PTR)hook - (LONG_PTR)((BYTE *)target + 5);
        VirtualProtect(target, 5, op, &op);
        FlushInstructionCache(GetCurrentProcess(), target, 5);
    }
}

/* TerminateProcess self-call bypasses the ExitProcess/RtlExitUserProcess
   hooks entirely, which is exactly how the game left with exit 0. Log the
   caller and the exit code; only intercept self-termination so the launcher
   can still terminate other processes during teardown. */
static BOOL (WINAPI *real_TerminateProcess)(HANDLE, UINT) = NULL;
BOOL WINAPI TerminateProcess_hook(HANDLE hProcess, UINT uExitCode) {
    BOOL is_self = (hProcess == GetCurrentProcess()) ||
                   (GetProcessId(hProcess) == GetCurrentProcessId());
    char who[MAX_PATH + 32];
    describe_address(__builtin_return_address(0), who, sizeof(who));
    { char b[MAX_PATH + 96];
      wsprintfA(b, "MVP_TerminateProcess(self=%d, code=%u) caller=%s%s",
                is_self, uExitCode, who, is_self ? " BLOCKED" : "");
      proxy_log_file(b);
      fprintf(stderr, "%s\n", b); fflush(stderr); }
    if (is_self) Sleep(INFINITE);
    /* Non-self: pass through the real function without re-entering. */
    BOOL result;
    if (passthrough_lock_ready) EnterCriticalSection(&passthrough_lock);
    restore_bytes((void *)real_TerminateProcess, saved_TerminateProcess);
    result = real_TerminateProcess(hProcess, uExitCode);
    rehook((void *)real_TerminateProcess, (void *)TerminateProcess_hook);
    if (passthrough_lock_ready) LeaveCriticalSection(&passthrough_lock);
    return result;
}

/* NtTerminateProcess(NULL/self, status) is the lowest self-exit primitive;
   ExitProcess and TerminateProcess both funnel here. Hooking it catches an
   exit that reaches ntdll directly. */
typedef NTSTATUS (WINAPI *NtTerminateProcess_t)(HANDLE, NTSTATUS);
static NtTerminateProcess_t real_NtTerminateProcess = NULL;
NTSTATUS WINAPI NtTerminateProcess_hook(HANDLE hProcess, NTSTATUS status) {
    BOOL is_self = (hProcess == NULL) ||
                   (hProcess == GetCurrentProcess()) ||
                   (GetProcessId(hProcess) == GetCurrentProcessId());
    char who[MAX_PATH + 32];
    describe_address(__builtin_return_address(0), who, sizeof(who));
    { char b[MAX_PATH + 96];
      wsprintfA(b, "MVP_NtTerminateProcess(self=%d, status=0x%08X) caller=%s%s",
                is_self, (unsigned)status, who, is_self ? " BLOCKED" : "");
      proxy_log_file(b);
      fprintf(stderr, "%s\n", b); fflush(stderr); }
    if (is_self) Sleep(INFINITE);
    NTSTATUS result;
    if (passthrough_lock_ready) EnterCriticalSection(&passthrough_lock);
    restore_bytes((void *)real_NtTerminateProcess, saved_NtTerminateProcess);
    result = real_NtTerminateProcess(hProcess, status);
    rehook((void *)real_NtTerminateProcess, (void *)NtTerminateProcess_hook);
    if (passthrough_lock_ready) LeaveCriticalSection(&passthrough_lock);
    return result;
}

/* Also hook RtlExitUserProcess in ntdll — catches _exit() and exit() */
static VOID (WINAPI *real_RtlExitUserProcess)(NTSTATUS ExitStatus) = NULL;
void WINAPI RtlExitUserProcess_hook(NTSTATUS ExitStatus) {
    fprintf(stderr, "MVP_RtlExitUserProcess(0x%08X): BLOCKED\n", (unsigned)ExitStatus);
    fflush(stderr);
    Sleep(INFINITE);
}

/* VEH: log all exceptions to understand why the game exits.
   Run 2 proved the exit is a self NtTerminateProcess(0xC0000005) — an
   access violation, not a clean quit. Write the faulting address and its
   module+offset to proxy-debug.log (the small artifact that downloads
   reliably) so the crash site is identifiable without pulling the full
   multi-hundred-MB artifact or a debugger. */
LONG WINAPI crash_logger(PEXCEPTION_POINTERS ep) {
    if (ep && ep->ExceptionRecord) {
        DWORD code = ep->ExceptionRecord->ExceptionCode;
        /* Filter out common non-fatal exceptions */
        if (code != 0xE06D7363 &&  /* C++ exception */
            code != 0x406D1388 &&  /* SetThreadName */
            code != STATUS_BREAKPOINT &&
            code != STATUS_SINGLE_STEP) {
            void *addr = ep->ExceptionRecord->ExceptionAddress;
            char where[MAX_PATH + 32];
            describe_address(addr, where, sizeof(where));
            char b[MAX_PATH + 128];
            /* For an access violation, ExceptionInformation[1] is the
               faulting data address (what it tried to read/write). */
            unsigned info1 = 0;
            if (code == 0xC0000005 &&
                ep->ExceptionRecord->NumberParameters >= 2) {
                info1 = (unsigned)ep->ExceptionRecord->ExceptionInformation[1];
            }
            wsprintfA(b, "MVP_EXC code=0x%08X addr=%p (%s) fault_data=0x%08X",
                      (unsigned)code, addr, where, info1);
            proxy_log_file(b);
            fprintf(stderr, "%s\n", b); fflush(stderr);
            /* Access-violation crash site is a member fn called on a NULL
               this. Which manager? Scan the stack for return addresses in the
               game image so the caller chain is identifiable without a
               debugger. Only the main game exe's .text (0x401000..0x460000)
               is reported; adjacent bytes 0xE8 (call rel32) before the target
               confirm a real return address. */
            if (code == 0xC0000005 && ep->ContextRecord) {
                DWORD *sp = (DWORD *)ep->ContextRecord->Esp;
                HMODULE exe = GetModuleHandleA(NULL);
                int found = 0;
                for (int i = 0; i < 256 && found < 8; i++) {
                    DWORD v;
                    /* Guard against walking off the stack. */
                    if (IsBadReadPtr(&sp[i], sizeof(DWORD))) break;
                    v = sp[i];
                    if (v < 0x401000 || v >= 0x460000) continue;
                    if (IsBadReadPtr((void *)(v - 5), 5)) continue;
                    if (*(BYTE *)(v - 5) != 0xE8) continue;  /* call rel32 */
                    char frame[MAX_PATH + 48];
                    char w2[MAX_PATH + 32];
                    describe_address((void *)v, w2, sizeof(w2));
                    wsprintfA(frame, "MVP_STACK[%d] ret=0x%08X (%s)",
                              found, (unsigned)v, w2);
                    proxy_log_file(frame);
                    fprintf(stderr, "%s\n", frame); fflush(stderr);
                    found++;
                }
                (void)exe;

                /* The flight voice path is built by MulleMeck.exe+0x1B1D0 via
                   sprintf into the fixed .data buffer 0x0045F0F4, and no other
                   build runs between that and this crash. So the buffer still
                   holds the exact resource path whose load returned NULL —
                   read it directly, no game-code patch needed. Dump once. */
                static LONG dumped = 0;
                if (InterlockedExchange(&dumped, 1) == 0) {
                    const char *buf = (const char *)0x0045F0F4u;
                    if (!IsBadReadPtr(buf, 1)) {
                        char nb[300];
                        wsprintfA(nb, "MVP_VOICEPATH \"%.255s\"", buf);
                        proxy_log_file(nb);
                        fprintf(stderr, "%s\n", nb); fflush(stderr);
                    }
                }
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Overwrite the first 5 bytes of `target` with a JMP rel32 to `hook`.
   Returns TRUE on success. Keeps the exit-hook installer readable now that
   several ntdll/kernel32 entry points get patched the same way. */
static BOOL patch_jmp(void *target, void *hook, const char *label) {
    if (!target) return FALSE;
    BYTE *code = (BYTE *)target;
    DWORD old_protect;
    if (!VirtualProtect(code, 5, PAGE_EXECUTE_READWRITE, &old_protect))
        return FALSE;
    code[0] = 0xE9;
    *(LONG_PTR *)(code + 1) = (LONG_PTR)hook - (LONG_PTR)(code + 5);
    VirtualProtect(code, 5, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), code, 5);
    { char b[128]; wsprintfA(b, "MVP: %s hook installed at %p", label, target);
      proxy_log_file(b); fprintf(stderr, "%s\n", b); fflush(stderr); }
    return TRUE;
}

static void install_exit_hook(void) {
    /* Install VEH first to catch crashes */
    AddVectoredExceptionHandler(0, crash_logger);
    fprintf(stderr, "MVP: VEH crash logger installed\n"); fflush(stderr);

    if (!passthrough_lock_ready) {
        InitializeCriticalSection(&passthrough_lock);
        passthrough_lock_ready = TRUE;
    }
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (k32) {
        real_TerminateProcess =
            (BOOL (WINAPI *)(HANDLE, UINT))GetProcAddress(k32, "TerminateProcess");
        if (real_TerminateProcess) {
            memcpy(saved_TerminateProcess, (void *)real_TerminateProcess, 5);
            patch_jmp((void *)real_TerminateProcess, (void *)TerminateProcess_hook,
                      "TerminateProcess");
        }
    }
    if (nt) {
        real_NtTerminateProcess =
            (NtTerminateProcess_t)GetProcAddress(nt, "NtTerminateProcess");
        if (real_NtTerminateProcess) {
            memcpy(saved_NtTerminateProcess, (void *)real_NtTerminateProcess, 5);
            patch_jmp((void *)real_NtTerminateProcess, (void *)NtTerminateProcess_hook,
                      "NtTerminateProcess");
        }
    }

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
    
    /* Also hook RtlExitUserProcess in ntdll */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        FARPROC rtl_exit = GetProcAddress(ntdll, "RtlExitUserProcess");
        if (rtl_exit) {
            BYTE *rtl_code = (BYTE*)rtl_exit;
            if (VirtualProtect(rtl_code, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
                LONG_PTR rtl_offset = (LONG_PTR)RtlExitUserProcess_hook - (LONG_PTR)(rtl_code + 5);
                rtl_code[0] = 0xE9;
                *(LONG_PTR*)(rtl_code + 1) = rtl_offset;
                VirtualProtect(rtl_code, 5, old_protect, &old_protect);
                FlushInstructionCache(GetCurrentProcess(), rtl_code, 5);
                fprintf(stderr, "MVP: RtlExitUserProcess hook installed at %p\n", rtl_code);
                fflush(stderr);
            }
        }
    }
    }
}

/* === ddraw.dll!DirectDrawCreate trampoline + vtable probe ===
 *
 * patch_jmp (above) overwrites 5 bytes with a JMP rel32 but keeps NO copy of
 * the original prologue, so a hook installed that way cannot call the real
 * function. To observe DirectDrawCreate AND still run it, we build a classic
 * inline-trampoline:
 *
 *   trampoline: [original 5 prologue bytes][E9 rel32 -> real+5]
 *
 * The hook calls the trampoline (= runs the real function) and then inspects
 * the COM object that came back. We dump the vtable pointer plus the
 * QueryInterface (vtbl[0]), SetDisplayMode (vtbl[0x54/4 == 21]) and
 * WaitForVerticalBlank (vtbl[0x58/4 == 22]) slots, and patch vtbl[0]
 * (QueryInterface) with a logging wrapper that prints the 16-byte riid so we
 * can distinguish IID_IDirectDraw2 {B3A6F3E0-2DEA-11CF-A9CD-00AA006C1000}
 * from IID_IDirectDraw7 {15E65EC0-3B9C-11D2-B92F-00609797EA5B}.
 *
 * RELOCATION NOTE: the first 5 bytes are copied VERBATIM. Any instruction with
 * a relative operand (call/jmp/jcc rel8|rel32, 0x9A call abs ptr16:32, 0xE0-0xE3
 * loop/jcxz) would compute its target against the ORIGINAL address and misfire
 * from the trampoline. Wine/mingw's DirectDrawCreate is a plain C prologue
 * (push ebp; mov ebp,esp; ...) so it should be safe; we dump the bytes and bail
 * loudly if a risky opcode is detected. */

/* The trampoline region (5 copied bytes + 5-byte JMP back). */
static unsigned char *ddraw_trampoline = NULL;

/* Saved real QueryInterface so the logging wrapper can forward. */
static void *ddraw_saved_QI = NULL;

/* Guard so we patch only the first created object's vtable (avoids clobbering
   ddraw_saved_QI across objects that may have different real QI impls). */
static BOOL ddraw_qi_patched = FALSE;

typedef HRESULT(WINAPI *DirectDrawCreate_t)(void *lpGUID, void **lplpDD,
                                            void *pUnkOuter);
typedef HRESULT(WINAPI *QueryInterface_t)(void *thisptr, const void *riid,
                                          void **ppv);

/* COM QueryInterface logging wrapper. stdcall: this, riid, ppv on stack. The
   riid GUID is {Data1(4 LE), Data2(2 LE), Data3(2 LE), Data4[8]}, so printing
   the raw bytes in order yields the canonical GUID string form. */
static HRESULT WINAPI ddraw_QI_hook(void *thisptr, const void *riid, void **ppv)
{
    if (riid && !IsBadReadPtr(riid, 16)) {
        const unsigned char *g = (const unsigned char *)riid;
        char b[128];
        wsprintfA(b,
                   "MVP_QI riid=%02X%02X%02X%02X-%02X%02X-%02X%02X-"
                   "%02X%02X-%02X%02X%02X%02X%02X%02X",
                   g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7],
                   g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
        proxy_log_file(b);
    }
    if (ddraw_saved_QI)
        return ((QueryInterface_t)ddraw_saved_QI)(thisptr, riid, ppv);
    return (HRESULT)0x80004002L; /* E_NOINTERFACE */
}

/* DirectDrawCreate hook: call the real fn via the trampoline, then read back
   the object's vtable and patch its QueryInterface slot. */
static HRESULT WINAPI DirectDrawCreate_hook(void *lpGUID, void **lplpDD,
                                            void *pUnkOuter)
{
    proxy_log_file("MVP_DDCREATE enter");
    HRESULT hr = ((DirectDrawCreate_t)(void *)ddraw_trampoline)(
        lpGUID, lplpDD, pUnkOuter);
    {
        char rb[96];
        wsprintfA(rb, "MVP_DDCREATE hr=0x%08X", (unsigned)hr);
        proxy_log_file(rb);
    }
    if (SUCCEEDED(hr) && lplpDD && *lplpDD) {
        void *obj = *lplpDD;
        /* Object's first DWORD is the COM vtable pointer. */
        if (!IsBadReadPtr(obj, sizeof(void *))) {
            void **vtbl = *(void ***)obj;
            char b[256];
            wsprintfA(b,
                       "MVP_DDV obj=%p vtbl=%p QI[0]=%p "
                       "SetDisplayMode[21]=%p WaitForVB[22]=%p",
                       obj, vtbl, vtbl[0], vtbl[21], vtbl[22]);
            proxy_log_file(b);
            /* Patch vtbl[0] (QueryInterface) to log every requested riid.
               Only do this once: a second object may have a different real QI
               and overwriting ddraw_saved_QI would corrupt it. */
            if (!ddraw_qi_patched &&
                !IsBadReadPtr(&vtbl[0], sizeof(void *))) {
                ddraw_saved_QI = vtbl[0];
                DWORD op;
                if (VirtualProtect(&vtbl[0], sizeof(void *),
                                   PAGE_READWRITE, &op)) {
                    vtbl[0] = (void *)ddraw_QI_hook;
                    VirtualProtect(&vtbl[0], sizeof(void *), op, &op);
                    FlushInstructionCache(GetCurrentProcess(),
                                          &vtbl[0], sizeof(void *));
                    ddraw_qi_patched = TRUE;
                    proxy_log_file("MVP_DDV QI vtable patched");
                } else {
                    proxy_log_file(
                        "MVP_DDV QI vtable patch FAILED (VirtualProtect)");
                }
            }
        }
    }
    return hr;
}

/* SetDisplayMode -> DD_OK stub. The game (gtSoftware) loops SetDisplayMode
   forever because headless Wine returns DDERR_UNSUPPORTED; returning DD_OK(0)
   makes it accept the mode and proceed to windowed rendering so the Manager
   constructs. __stdcall COM method: this + 5 args (w,h,bpp,refresh,flags) for
   IDirectDraw2/4/7 = 24 bytes = ret 0x18. (CreateEx always yields DD4/DD7,
   whose SetDisplayMode is the 5-arg form at vtable index 21.) */
static __attribute__((naked)) void set_display_mode_stub(void)
{
    __asm__ __volatile__("xorl %eax, %eax\n\tret $0x18\n");
}

static BOOL ddraw_sdm_patched = FALSE;
static unsigned char *ddraw_ex_trampoline = NULL;
typedef HRESULT(WINAPI *DirectDrawCreateEx_t)(void *lpGUID, void **lplpDD,
                                              const void *iid, void *pUnkOuter);

/* Patch the SetDisplayMode slot (vtable index 21) of a created DirectDraw
   object to the DD_OK stub, VirtualProtect-guarded, once. */
static void patch_setdisplaymode(void *obj)
{
    if (ddraw_sdm_patched || !obj || IsBadReadPtr(obj, sizeof(void *))) return;
    {
        void **vtbl = *(void ***)obj;
        DWORD op;
        char b[128];
        wsprintfA(b, "MVP_DDEX obj=%p vtbl=%p SetDisplayMode[21]=%p",
                  obj, vtbl, vtbl[21]);
        proxy_log_file(b);
        if (!IsBadReadPtr(&vtbl[21], sizeof(void *)) &&
            VirtualProtect(&vtbl[21], sizeof(void *), PAGE_READWRITE, &op)) {
            vtbl[21] = (void *)set_display_mode_stub;
            VirtualProtect(&vtbl[21], sizeof(void *), op, &op);
            FlushInstructionCache(GetCurrentProcess(), &vtbl[21],
                                  sizeof(void *));
            ddraw_sdm_patched = TRUE;
            proxy_log_file("MVP_DDEX SetDisplayMode patched -> DD_OK");
        } else {
            proxy_log_file("MVP_DDEX SetDisplayMode patch FAILED");
        }
    }
}

/* DirectDrawCreateEx hook: gtSoftware creates its DirectDraw via CreateEx
   (returns IDirectDraw7), not DirectDrawCreate — so this is where we patch. */
static HRESULT WINAPI DirectDrawCreateEx_hook(void *lpGUID, void **lplpDD,
                                              const void *iid, void *pUnkOuter)
{
    proxy_log_file("MVP_DDEX enter");
    HRESULT hr = ((DirectDrawCreateEx_t)(void *)ddraw_ex_trampoline)(
        lpGUID, lplpDD, iid, pUnkOuter);
    if (iid && !IsBadReadPtr(iid, 16)) {
        const unsigned char *g = (const unsigned char *)iid;
        char b[128];
        wsprintfA(b, "MVP_DDEX iid=%02X%02X%02X%02X-%02X%02X-%02X%02X-"
                  "%02X%02X-%02X%02X%02X%02X%02X%02X",
                  g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7],
                  g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
        proxy_log_file(b);
    }
    if (SUCCEEDED(hr) && lplpDD && *lplpDD) patch_setdisplaymode(*lplpDD);
    return hr;
}

/* Build an inline trampoline for `real` (5 copied bytes + JMP to real+5) and
   patch real -> hook. Returns the trampoline, or NULL on unsafe prologue. */
static unsigned char *install_export_trampoline(unsigned char *real,
                                                void *hook, const char *label)
{
    unsigned char c0 = real[0];
    unsigned char *tramp;
    LONG_PTR back;
    if (c0 == 0xE8 || c0 == 0xE9 || c0 == 0xEB || c0 == 0x9A ||
        (c0 >= 0x70 && c0 <= 0x7F) || (c0 >= 0xE0 && c0 <= 0xE3) ||
        (c0 == 0x0F && !IsBadReadPtr(real + 1, 1) &&
         real[1] >= 0x80 && real[1] <= 0x8F)) {
        proxy_log_file("MVP_DDEX ABORT: unsafe prologue");
        return NULL;
    }
    tramp = (unsigned char *)VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (!tramp) return NULL;
    memcpy(tramp, real, 5);
    back = (LONG_PTR)(real + 5) - (LONG_PTR)(tramp + 10);
    tramp[5] = 0xE9;
    *(LONG_PTR *)(tramp + 6) = back;
    patch_jmp(real, hook, label);
    return tramp;
}

static void install_ddraw_hook(void)
{
    HMODULE ddraw = GetModuleHandleA("ddraw.dll");
    if (!ddraw) return;
    /* gtSoftware uses DirectDrawCreateEx (DD7) — hook it and patch
       SetDisplayMode -> DD_OK directly. */
    {
        FARPROC ex = GetProcAddress(ddraw, "DirectDrawCreateEx");
        if (ex && !ddraw_ex_trampoline) {
            ddraw_ex_trampoline = install_export_trampoline(
                (unsigned char *)ex, (void *)DirectDrawCreateEx_hook,
                "DirectDrawCreateEx");
        }
    }
    FARPROC proc = GetProcAddress(ddraw, "DirectDrawCreate");
    if (!proc) {
        proxy_log_file("MVP_DDRAW DirectDrawCreate not found");
        return;
    }

    unsigned char *real = (unsigned char *)proc;

    /* Dump the prologue bytes so relocation safety is verifiable from the log.
       Read into locals first (arg eval order is unspecified). */
    {
        unsigned char p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0,
                      p5 = 0, p6 = 0, p7 = 0;
        p0 = real[0]; p1 = real[1]; p2 = real[2]; p3 = real[3]; p4 = real[4];
        if (!IsBadReadPtr(real, 8)) {
            p5 = real[5]; p6 = real[6]; p7 = real[7];
        }
        char b[160];
        wsprintfA(b,
                   "MVP_DDRAW DirectDrawCreate @ %p "
                   "prologue=%02X %02X %02X %02X %02X %02X %02X %02X",
                   real, p0, p1, p2, p3, p4, p5, p6, p7);
        proxy_log_file(b);
    }

    /* Relocation-safety check for the first 5 bytes. */
    {
        unsigned char c0 = real[0];
        BOOL risky = FALSE;
        if (c0 == 0xE8 || c0 == 0xE9 || c0 == 0xEB || c0 == 0x9A ||
            (c0 >= 0x70 && c0 <= 0x7F) || (c0 >= 0xE0 && c0 <= 0xE3)) {
            risky = TRUE;
        }
        if (c0 == 0x0F && !IsBadReadPtr(real + 1, 1) &&
            real[1] >= 0x80 && real[1] <= 0x8F) {
            risky = TRUE; /* 0F 8x jcc rel32 (6 bytes) */
        }
        if (risky) {
            proxy_log_file(
                "MVP_DDRAW ABORT: prologue has relative opcode, "
                "trampoline unsafe");
            return;
        }
    }

    /* Build trampoline: [5 original bytes][E9 rel32 -> real+5]. */
    ddraw_trampoline = (unsigned char *)VirtualAlloc(
        NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ddraw_trampoline) {
        proxy_log_file("MVP_DDRAW trampoline alloc FAILED");
        return;
    }
    memcpy(ddraw_trampoline, real, 5);
    LONG_PTR back = (LONG_PTR)(real + 5) - (LONG_PTR)(ddraw_trampoline + 10);
    ddraw_trampoline[5] = 0xE9; /* JMP rel32 */
    *(LONG_PTR *)(ddraw_trampoline + 6) = back;

    /* Patch real DirectDrawCreate -> our hook (uses patch_jmp above). */
    patch_jmp(real, (void *)DirectDrawCreate_hook, "DirectDrawCreate");
}
