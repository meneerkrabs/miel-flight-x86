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
    fprintf(stderr, "MVP_ExitProcess(%u): BLOCKED\n", uExitCode); fflush(stderr);
    Sleep(INFINITE);
}

void WINAPI PostQuitMessage_hook(int nExitCode) {
    fprintf(stderr, "MVP_PostQuitMessage(%d): BLOCKED\n", nExitCode); fflush(stderr);
    /* Do nothing — don't post WM_QUIT, keep the game alive */
}

static void install_exit_hook(void) {
    HMODULE exe_module = GetModuleHandleA(NULL);
    if (!exe_module) return;
    BYTE *base = (BYTE*)exe_module;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!import_rva) return;
    IMAGE_IMPORT_DESCRIPTOR *imports = (IMAGE_IMPORT_DESCRIPTOR*)(base + import_rva);
    DWORD old_protect;
    int hooked = 0;
    for (; imports->Name; imports++) {
        IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA*)(base + imports->FirstThunk);
        IMAGE_THUNK_DATA *orig_thunk = (IMAGE_THUNK_DATA*)
            (base + (imports->OriginalFirstThunk ? imports->OriginalFirstThunk : imports->FirstThunk));
        for (; orig_thunk->u1.AddressOfData; thunk++, orig_thunk++) {
            if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            IMAGE_IMPORT_BY_NAME *import = (IMAGE_IMPORT_BY_NAME*)(base + orig_thunk->u1.AddressOfData);
            if (lstrcmpiA(import->Name, "ExitProcess") == 0) {
                VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old_protect);
                thunk->u1.Function = (ULONG_PTR)ExitProcess_hook;
                VirtualProtect(&thunk->u1.Function, sizeof(void*), old_protect, &old_protect);
                hooked++;
            } else if (lstrcmpiA(import->Name, "PostQuitMessage") == 0) {
                VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old_protect);
                thunk->u1.Function = (ULONG_PTR)PostQuitMessage_hook;
                VirtualProtect(&thunk->u1.Function, sizeof(void*), old_protect, &old_protect);
                hooked++;
            }
        }
    }
    fprintf(stderr, "MVP: %d exit hooks installed\n", hooked); fflush(stderr);
}
