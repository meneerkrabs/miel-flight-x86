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

/* === Factory probe: log why 0x409910 returns NULL ===
   The resource factory returned NULL loading the flight voice. Its two NULL
   paths are owner->dir (at owner+0x14) being NULL, or operator new failing.
   Log the owner, owner->dir and the requested name on the first call, then
   jump through a trampoline so the original runs untouched — a plain
   log-and-continue JMP hook (no unhook/rehook, no return wrap), which is
   safe even on a hot path. */
#define FACTORY_VA 0x00409910u
/* Pin the assembler names so the global-asm stub links on both the CI
   MSYS2 i686 toolchain (no leading underscore) and other i686 toolchains
   (leading underscore) — the explicit asm() name removes the ambiguity. */
static void *factory_tramp_ptr asm("factory_tramp_ptr") = NULL;
static BYTE factory_tramp[16];

void __cdecl log_factory_c(void *owner, const char *name) asm("log_factory_c");
void __cdecl log_factory_c(void *owner, const char *name) {
    static LONG once = 0;
    if (InterlockedExchange(&once, 1) != 0) return;
    const char *dir = "(owner null)";
    if (owner && !IsBadReadPtr((BYTE *)owner + 0x14, 4)) {
        char **pdir = (char **)((BYTE *)owner + 0x14);
        dir = (*pdir && !IsBadReadPtr(*pdir, 1)) ? *pdir : "(NULL dir)";
    }
    char nb[420];
    wsprintfA(nb, "MVP_FACTORY owner=%p dir=\"%.160s\" name=\"%.160s\"",
              owner, dir,
              (name && !IsBadReadPtr(name, 1)) ? name : "(?)");
    proxy_log_file(nb);
    fprintf(stderr, "%s\n", nb); fflush(stderr);
}

/* mingw-w64 i686 emits C symbols without a leading underscore, so the asm
   must reference the bare names. */
extern void factory_probe(void) asm("factory_probe");
__asm__(
".text\n"
".globl factory_probe\n"
"factory_probe:\n"
"  pushfl\n"
"  pushal\n"
"  movl 40(%esp), %eax\n"   /* arg1 name: pushfl4 + pushal32 + retaddr4 */
"  movl %ecx, %edx\n"       /* ecx = this (owner), still live after pushal */
"  pushl %eax\n"
"  pushl %edx\n"
"  call log_factory_c\n"
"  addl $8, %esp\n"
"  popal\n"
"  popfl\n"
"  jmp *factory_tramp_ptr\n"
);

static void install_factory_probe(void) {
    BYTE *fac = (BYTE *)FACTORY_VA;
    if (IsBadReadPtr(fac, 7)) return;
    DWORD op;
    /* trampoline = original 7 bytes (push -1 ; push imm32, both absolute) +
       jmp back to fac+7 */
    if (!VirtualProtect(factory_tramp, sizeof(factory_tramp),
                        PAGE_EXECUTE_READWRITE, &op)) return;
    memcpy(factory_tramp, fac, 7);
    factory_tramp[7] = 0xE9;
    *(LONG *)(factory_tramp + 8) =
        (LONG)(fac + 7) - (LONG)(factory_tramp + 7 + 5);
    factory_tramp_ptr = factory_tramp;
    FlushInstructionCache(GetCurrentProcess(), factory_tramp,
                          sizeof(factory_tramp));
    if (VirtualProtect(fac, 5, PAGE_EXECUTE_READWRITE, &op)) {
        fac[0] = 0xE9;
        *(LONG *)(fac + 1) = (LONG)factory_probe - (LONG)(fac + 5);
        VirtualProtect(fac, 5, op, &op);
        FlushInstructionCache(GetCurrentProcess(), fac, 5);
        proxy_log_file("MVP: factory probe installed at 0x409910");
    }
}

static void install_exit_hook(void) {
    /* Install VEH first to catch crashes */
    AddVectoredExceptionHandler(0, crash_logger);
    fprintf(stderr, "MVP: VEH crash logger installed\n"); fflush(stderr);
    install_factory_probe();

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
