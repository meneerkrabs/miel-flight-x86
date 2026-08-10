#define WIN32_LEAN_AND_MEAN
#define DIRECTINPUT_VERSION 0x0500
#include <windows.h>
#include <dinput.h>
typedef LONG NTSTATUS;
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>

typedef HRESULT (WINAPI *DirectInputCreateAFunction)(
    HINSTANCE, DWORD, LPDIRECTINPUTA *, LPUNKNOWN);
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

static void install_exit_hook(void);

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

/* === Headless DirectInput boot adapter ===
   Wine's real DirectInputCreateA enters an internal device/event wait before
   returning its COM object. Patching public device methods cannot reach that
   wait, so the headless capture path must not enter wine-dinput at all.

   These are real DirectInput 5 COM objects, not untyped arrays: MinGW's
   IDirectInputAVtbl/IDirectInputDeviceAVtbl declarations pin every slot and
   every WINAPI (__stdcall) argument count. That lets the compiler emit the
   required x86 `ret N` cleanup from the reviewed interface signatures instead
   of duplicating byte counts in handwritten assembly. Input replay is a later
   adapter; this boot implementation deliberately returns neutral state. */
typedef struct FakeDirectInput {
    const IDirectInputAVtbl *lpVtbl;
    LONG references;
} FakeDirectInput;

typedef struct FakeDirectInputDevice {
    const IDirectInputDeviceAVtbl *lpVtbl;
    LONG references;
} FakeDirectInputDevice;

static const IDirectInputAVtbl fake_direct_input_vtbl;
static const IDirectInputDeviceAVtbl fake_direct_input_device_vtbl;

/* Record each COM entry point once. The sequence number turns a headless CI
   timeout into a bounded call-path receipt without flooding polling methods. */
enum FakeDirectInputTraceSlot {
    FAKE_DI_TRACE_QI, FAKE_DI_TRACE_ADDREF, FAKE_DI_TRACE_RELEASE,
    FAKE_DI_TRACE_CREATE_DEVICE, FAKE_DI_TRACE_ENUM_DEVICES,
    FAKE_DI_TRACE_GET_DEVICE_STATUS, FAKE_DI_TRACE_RUN_CONTROL_PANEL,
    FAKE_DI_TRACE_INITIALIZE, FAKE_DEVICE_TRACE_QI,
    FAKE_DEVICE_TRACE_ADDREF, FAKE_DEVICE_TRACE_RELEASE,
    FAKE_DEVICE_TRACE_GET_CAPABILITIES, FAKE_DEVICE_TRACE_ENUM_OBJECTS,
    FAKE_DEVICE_TRACE_GET_PROPERTY, FAKE_DEVICE_TRACE_SET_PROPERTY,
    FAKE_DEVICE_TRACE_ACQUIRE, FAKE_DEVICE_TRACE_UNACQUIRE,
    FAKE_DEVICE_TRACE_GET_STATE, FAKE_DEVICE_TRACE_GET_DATA,
    FAKE_DEVICE_TRACE_SET_DATA_FORMAT, FAKE_DEVICE_TRACE_SET_EVENT,
    FAKE_DEVICE_TRACE_SET_COOPERATIVE_LEVEL,
    FAKE_DEVICE_TRACE_GET_OBJECT_INFO, FAKE_DEVICE_TRACE_GET_DEVICE_INFO,
    FAKE_DEVICE_TRACE_DEVICE_RUN_CONTROL_PANEL,
    FAKE_DEVICE_TRACE_INITIALIZE, FAKE_DI_TRACE_SLOT_COUNT
};

static volatile LONG fake_di_trace_seen[FAKE_DI_TRACE_SLOT_COUNT];
static volatile LONG fake_di_trace_sequence;

static void fake_di_trace_once(enum FakeDirectInputTraceSlot slot,
                               const char *method)
{
    char line[160];
    LONG sequence;
    if (slot < 0 || slot >= FAKE_DI_TRACE_SLOT_COUNT) return;
    if (InterlockedCompareExchange(&fake_di_trace_seen[slot], 1, 0) != 0) {
        return;
    }
    sequence = InterlockedIncrement(&fake_di_trace_sequence);
    wsprintfA(line, "MVP_DI call sequence=%ld method=%s", sequence, method);
    proxy_log_file(line);
}

/* Local IID constants avoid adding a uuid-library link dependency to the
   proxy while keeping QueryInterface strict. */
static const GUID fake_iid_iunknown = {
    0x00000000, 0x0000, 0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};
static const GUID fake_iid_direct_input_a = {
    0x89521360, 0xAA8A, 0x11CF,
    {0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}
};
static const GUID fake_iid_direct_input_device_a = {
    0x5944E680, 0xC92E, 0x11CF,
    {0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}
};

_Static_assert(sizeof(void *) == 4, "DINPUT proxy requires the x86 COM ABI");
_Static_assert(offsetof(IDirectInputAVtbl, CreateDevice) == 3 * sizeof(void *),
               "IDirectInputA::CreateDevice must remain vtable slot 3");
_Static_assert(offsetof(IDirectInputDeviceAVtbl, Acquire) == 7 * sizeof(void *),
               "IDirectInputDeviceA::Acquire must remain vtable slot 7");
_Static_assert(offsetof(IDirectInputDeviceAVtbl, GetDeviceState) ==
               9 * sizeof(void *),
               "IDirectInputDeviceA::GetDeviceState must remain slot 9");
_Static_assert(offsetof(IDirectInputDeviceAVtbl, SetDataFormat) ==
               11 * sizeof(void *),
               "IDirectInputDeviceA::SetDataFormat must remain slot 11");
_Static_assert(offsetof(IDirectInputDeviceAVtbl, SetCooperativeLevel) ==
               13 * sizeof(void *),
               "IDirectInputDeviceA::SetCooperativeLevel must remain slot 13");

static BOOL fake_iid_equal(REFIID left, const GUID *right)
{
    return left && !memcmp(left, right, sizeof(*right));
}

static HRESULT WINAPI fake_di_QueryInterface(IDirectInputA *iface, REFIID iid,
                                              void **result)
{
    fake_di_trace_once(FAKE_DI_TRACE_QI, "IDirectInputA::QueryInterface");
    if (!result) return E_POINTER;
    *result = NULL;
    if (!fake_iid_equal(iid, &fake_iid_iunknown) &&
        !fake_iid_equal(iid, &fake_iid_direct_input_a)) {
        return E_NOINTERFACE;
    }
    *result = iface;
    iface->lpVtbl->AddRef(iface);
    return S_OK;
}

static ULONG WINAPI fake_di_AddRef(IDirectInputA *iface)
{
    fake_di_trace_once(FAKE_DI_TRACE_ADDREF, "IDirectInputA::AddRef");
    FakeDirectInput *self = (FakeDirectInput *)iface;
    return (ULONG)InterlockedIncrement(&self->references);
}

static ULONG WINAPI fake_di_Release(IDirectInputA *iface)
{
    fake_di_trace_once(FAKE_DI_TRACE_RELEASE, "IDirectInputA::Release");
    FakeDirectInput *self = (FakeDirectInput *)iface;
    LONG references = InterlockedDecrement(&self->references);
    if (references == 0) HeapFree(GetProcessHeap(), 0, self);
    return (ULONG)references;
}

static HRESULT WINAPI fake_device_QueryInterface(IDirectInputDeviceA *iface,
                                                  REFIID iid, void **result)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_QI,
                       "IDirectInputDeviceA::QueryInterface");
    if (!result) return E_POINTER;
    *result = NULL;
    if (!fake_iid_equal(iid, &fake_iid_iunknown) &&
        !fake_iid_equal(iid, &fake_iid_direct_input_device_a)) {
        return E_NOINTERFACE;
    }
    *result = iface;
    iface->lpVtbl->AddRef(iface);
    return S_OK;
}

static ULONG WINAPI fake_device_AddRef(IDirectInputDeviceA *iface)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_ADDREF,
                       "IDirectInputDeviceA::AddRef");
    FakeDirectInputDevice *self = (FakeDirectInputDevice *)iface;
    return (ULONG)InterlockedIncrement(&self->references);
}

static ULONG WINAPI fake_device_Release(IDirectInputDeviceA *iface)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_RELEASE,
                       "IDirectInputDeviceA::Release");
    FakeDirectInputDevice *self = (FakeDirectInputDevice *)iface;
    LONG references = InterlockedDecrement(&self->references);
    if (references == 0) HeapFree(GetProcessHeap(), 0, self);
    return (ULONG)references;
}

static HRESULT WINAPI fake_di_CreateDevice(IDirectInputA *iface, REFGUID guid,
                                           LPDIRECTINPUTDEVICEA *result,
                                           LPUNKNOWN outer)
{
    FakeDirectInputDevice *device;
    fake_di_trace_once(FAKE_DI_TRACE_CREATE_DEVICE,
                       "IDirectInputA::CreateDevice");
    (void)iface;
    (void)guid;
    if (!result) return E_POINTER;
    *result = NULL;
    if (outer) return CLASS_E_NOAGGREGATION;
    device = (FakeDirectInputDevice *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*device));
    if (!device) return E_OUTOFMEMORY;
    device->lpVtbl = &fake_direct_input_device_vtbl;
    device->references = 1;
    *result = (LPDIRECTINPUTDEVICEA)device;
    proxy_log_file("MVP_DI fake IDirectInputDeviceA created");
    return DI_OK;
}

static HRESULT WINAPI fake_di_EnumDevices(IDirectInputA *iface, DWORD type,
                                          LPDIENUMDEVICESCALLBACKA callback,
                                          LPVOID reference, DWORD flags)
{
    fake_di_trace_once(FAKE_DI_TRACE_ENUM_DEVICES,
                       "IDirectInputA::EnumDevices");
    (void)iface;
    (void)type;
    (void)callback;
    (void)reference;
    (void)flags;
    return DI_OK;
}

static HRESULT WINAPI fake_di_GetDeviceStatus(IDirectInputA *iface,
                                               REFGUID guid)
{
    fake_di_trace_once(FAKE_DI_TRACE_GET_DEVICE_STATUS,
                       "IDirectInputA::GetDeviceStatus");
    (void)iface;
    (void)guid;
    return DI_OK;
}

static HRESULT WINAPI fake_di_RunControlPanel(IDirectInputA *iface, HWND owner,
                                              DWORD flags)
{
    fake_di_trace_once(FAKE_DI_TRACE_RUN_CONTROL_PANEL,
                       "IDirectInputA::RunControlPanel");
    (void)iface;
    (void)owner;
    (void)flags;
    return DI_OK;
}

static HRESULT WINAPI fake_di_Initialize(IDirectInputA *iface,
                                         HINSTANCE instance, DWORD version)
{
    fake_di_trace_once(FAKE_DI_TRACE_INITIALIZE, "IDirectInputA::Initialize");
    (void)iface;
    (void)instance;
    (void)version;
    return DI_OK;
}

static HRESULT WINAPI fake_device_GetCapabilities(IDirectInputDeviceA *iface,
                                                   LPDIDEVCAPS capabilities)
{
    DWORD size;
    fake_di_trace_once(FAKE_DEVICE_TRACE_GET_CAPABILITIES,
                       "IDirectInputDeviceA::GetCapabilities");
    (void)iface;
    if (!capabilities) return E_POINTER;
    size = capabilities->dwSize;
    if (size != sizeof(DIDEVCAPS) && size != sizeof(DIDEVCAPS_DX3)) {
        return DIERR_INVALIDPARAM;
    }
    ZeroMemory(capabilities, size);
    capabilities->dwSize = size;
    return DI_OK;
}

static HRESULT WINAPI fake_device_EnumObjects(
    IDirectInputDeviceA *iface, LPDIENUMDEVICEOBJECTSCALLBACKA callback,
    LPVOID reference, DWORD flags)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_ENUM_OBJECTS,
                       "IDirectInputDeviceA::EnumObjects");
    (void)iface;
    (void)callback;
    (void)reference;
    (void)flags;
    return DI_OK;
}

static HRESULT WINAPI fake_device_GetProperty(IDirectInputDeviceA *iface,
                                               REFGUID property,
                                               LPDIPROPHEADER value)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_GET_PROPERTY,
                       "IDirectInputDeviceA::GetProperty");
    (void)iface;
    (void)property;
    (void)value;
    return DI_OK;
}

static HRESULT WINAPI fake_device_SetProperty(IDirectInputDeviceA *iface,
                                               REFGUID property,
                                               LPCDIPROPHEADER value)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_SET_PROPERTY,
                       "IDirectInputDeviceA::SetProperty");
    (void)iface;
    (void)property;
    (void)value;
    return DI_OK;
}

static HRESULT WINAPI fake_device_Acquire(IDirectInputDeviceA *iface)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_ACQUIRE,
                       "IDirectInputDeviceA::Acquire");
    (void)iface;
    return DI_OK;
}

static HRESULT WINAPI fake_device_Unacquire(IDirectInputDeviceA *iface)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_UNACQUIRE,
                       "IDirectInputDeviceA::Unacquire");
    (void)iface;
    return DI_OK;
}

static HRESULT WINAPI fake_device_GetDeviceState(IDirectInputDeviceA *iface,
                                                  DWORD size, LPVOID state)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_GET_STATE,
                       "IDirectInputDeviceA::GetDeviceState");
    (void)iface;
    if (size && !state) return E_POINTER;
    if (size) ZeroMemory(state, size);
    return DI_OK;
}

static HRESULT WINAPI fake_device_GetDeviceData(
    IDirectInputDeviceA *iface, DWORD object_size,
    LPDIDEVICEOBJECTDATA data, LPDWORD count, DWORD flags)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_GET_DATA,
                       "IDirectInputDeviceA::GetDeviceData");
    (void)iface;
    (void)object_size;
    (void)data;
    (void)flags;
    if (!count) return E_POINTER;
    *count = 0;
    return DI_OK;
}

static HRESULT WINAPI fake_device_SetDataFormat(IDirectInputDeviceA *iface,
                                                 LPCDIDATAFORMAT format)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_SET_DATA_FORMAT,
                       "IDirectInputDeviceA::SetDataFormat");
    (void)iface;
    (void)format;
    return DI_OK;
}

static HRESULT WINAPI fake_device_SetEventNotification(
    IDirectInputDeviceA *iface, HANDLE event)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_SET_EVENT,
                       "IDirectInputDeviceA::SetEventNotification");
    (void)iface;
    (void)event;
    return DI_OK;
}

static HRESULT WINAPI fake_device_SetCooperativeLevel(
    IDirectInputDeviceA *iface, HWND window, DWORD flags)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_SET_COOPERATIVE_LEVEL,
                       "IDirectInputDeviceA::SetCooperativeLevel");
    (void)iface;
    (void)window;
    (void)flags;
    return DI_OK;
}

static HRESULT WINAPI fake_device_GetObjectInfo(
    IDirectInputDeviceA *iface, LPDIDEVICEOBJECTINSTANCEA info,
    DWORD object, DWORD how)
{
    DWORD size;
    fake_di_trace_once(FAKE_DEVICE_TRACE_GET_OBJECT_INFO,
                       "IDirectInputDeviceA::GetObjectInfo");
    (void)iface;
    (void)object;
    (void)how;
    if (!info) return E_POINTER;
    size = info->dwSize;
    if (size != sizeof(DIDEVICEOBJECTINSTANCEA) &&
        size != sizeof(DIDEVICEOBJECTINSTANCE_DX3A)) {
        return DIERR_INVALIDPARAM;
    }
    ZeroMemory(info, size);
    info->dwSize = size;
    return DI_OK;
}

static HRESULT WINAPI fake_device_GetDeviceInfo(IDirectInputDeviceA *iface,
                                                 LPDIDEVICEINSTANCEA info)
{
    DWORD size;
    fake_di_trace_once(FAKE_DEVICE_TRACE_GET_DEVICE_INFO,
                       "IDirectInputDeviceA::GetDeviceInfo");
    (void)iface;
    if (!info) return E_POINTER;
    size = info->dwSize;
    if (size != sizeof(DIDEVICEINSTANCEA) &&
        size != sizeof(DIDEVICEINSTANCE_DX3A)) {
        return DIERR_INVALIDPARAM;
    }
    ZeroMemory(info, size);
    info->dwSize = size;
    return DI_OK;
}

static HRESULT WINAPI fake_device_RunControlPanel(IDirectInputDeviceA *iface,
                                                  HWND owner, DWORD flags)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_DEVICE_RUN_CONTROL_PANEL,
                       "IDirectInputDeviceA::RunControlPanel");
    (void)iface;
    (void)owner;
    (void)flags;
    return DI_OK;
}

static HRESULT WINAPI fake_device_Initialize(IDirectInputDeviceA *iface,
                                             HINSTANCE instance,
                                             DWORD version, REFGUID guid)
{
    fake_di_trace_once(FAKE_DEVICE_TRACE_INITIALIZE,
                       "IDirectInputDeviceA::Initialize");
    (void)iface;
    (void)instance;
    (void)version;
    (void)guid;
    return DI_OK;
}

static const IDirectInputAVtbl fake_direct_input_vtbl = {
    fake_di_QueryInterface,
    fake_di_AddRef,
    fake_di_Release,
    fake_di_CreateDevice,
    fake_di_EnumDevices,
    fake_di_GetDeviceStatus,
    fake_di_RunControlPanel,
    fake_di_Initialize
};

static const IDirectInputDeviceAVtbl fake_direct_input_device_vtbl = {
    fake_device_QueryInterface,
    fake_device_AddRef,
    fake_device_Release,
    fake_device_GetCapabilities,
    fake_device_EnumObjects,
    fake_device_GetProperty,
    fake_device_SetProperty,
    fake_device_Acquire,
    fake_device_Unacquire,
    fake_device_GetDeviceState,
    fake_device_GetDeviceData,
    fake_device_SetDataFormat,
    fake_device_SetEventNotification,
    fake_device_SetCooperativeLevel,
    fake_device_GetObjectInfo,
    fake_device_GetDeviceInfo,
    fake_device_RunControlPanel,
    fake_device_Initialize
};

__declspec(dllexport) HRESULT WINAPI DirectInputCreateA(
    HINSTANCE instance, DWORD version, LPDIRECTINPUTA *direct_input,
    LPUNKNOWN outer)
{
    FakeDirectInput *fake;
    /* Try to initialize the observer proxy. If it fails (e.g. Cc.dll not
       loaded yet), the bootstrap thread retries observer initialization. Do
       not call real DirectInputCreateA here: Wine's implementation blocks in
       its internal headless device wait before any public COM method runs. */
    initialize_proxy();
    (void)instance;
    (void)version;
    if (!direct_input) return E_POINTER;
    *direct_input = NULL;
    if (outer) return CLASS_E_NOAGGREGATION;
    fake = (FakeDirectInput *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*fake));
    if (!fake) return E_OUTOFMEMORY;
    fake->lpVtbl = &fake_direct_input_vtbl;
    fake->references = 1;
    *direct_input = (LPDIRECTINPUTA)fake;
    proxy_log_file("MVP_DI fake IDirectInputA created; wine-dinput bypassed");
    return DI_OK;
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
    /* Install diagnostics only. Process termination must remain observable by
       the launcher; suppressing a clean exit turns a useful failure into a
       ten-minute bootstrap timeout. */
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
    /* The launcher already owns process-lifecycle observation. Keep the proxy
       limited to exception telemetry and never rewrite termination exports. */
    AddVectoredExceptionHandler(0, crash_logger);
    fprintf(stderr, "MVP: VEH crash logger installed\n"); fflush(stderr);
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
    {
        char b[128];
        void *object = (lplpDD && !IsBadReadPtr(lplpDD, sizeof(*lplpDD)))
            ? *lplpDD : NULL;
        wsprintfA(b, "MVP_DDEX result hr=0x%08X output=%p object=%p",
                  (unsigned)hr, lplpDD, object);
        proxy_log_file(b);
    }
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
