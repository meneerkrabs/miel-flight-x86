#define COBJMACROS
#define INITGUID
#include <dsound.h>
#include <mmdeviceapi.h>
#include <objbase.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

static BOOL parse_timeout_ms(const char *text, DWORD *value)
{
    unsigned long parsed = 0ul;
    const char *cursor = text;
    if (!text || !*text || !value) return FALSE;
    while (*cursor) {
        if (*cursor < '0' || *cursor > '9') return FALSE;
        parsed = parsed * 10ul + (unsigned long)(*cursor - '0');
        if (parsed > 120000ul) return FALSE;
        ++cursor;
    }
    if (parsed < 1000ul) return FALSE;
    *value = (DWORD)parsed;
    return TRUE;
}

static BOOL wait_for_rpcss(DWORD timeout_ms)
{
    SC_HANDLE manager = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS_PROCESS status;
    DWORD needed = 0u;
    DWORD started = GetTickCount();
    BOOL ready = FALSE;

    manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) goto cleanup;
    service = OpenServiceA(
        manager, "RpcSs", SERVICE_QUERY_STATUS | SERVICE_START);
    if (!service) goto cleanup;
    do {
        if (!QueryServiceStatusEx(
                service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status,
                sizeof(status), &needed)) goto cleanup;
        if (status.dwCurrentState == SERVICE_RUNNING) {
            ready = TRUE;
            break;
        }
        if (status.dwCurrentState == SERVICE_STOPPED &&
            !StartServiceA(service, 0u, NULL)) {
            DWORD error = GetLastError();
            if (error != ERROR_SERVICE_ALREADY_RUNNING &&
                error != ERROR_SERVICE_DATABASE_LOCKED) {
                goto cleanup;
            }
        }
        Sleep(100u);
    } while (GetTickCount() - started < timeout_ms);

cleanup:
    if (service) CloseServiceHandle(service);
    if (manager) CloseServiceHandle(manager);
    return ready;
}

static BOOL registry_class_exists(const char *clsid)
{
    char key_name[160];
    char value[MAX_PATH];
    DWORD type = 0u;
    DWORD size = sizeof(value);
    HKEY key = NULL;
    LONG result;

    if (snprintf(
            key_name, sizeof(key_name), "CLSID\\%s\\InprocServer32",
            clsid) <= 0) return FALSE;
    result = RegOpenKeyExA(
        HKEY_CLASSES_ROOT, key_name, 0u, KEY_QUERY_VALUE, &key);
    if (result != ERROR_SUCCESS) return FALSE;
    result = RegQueryValueExA(
        key, NULL, NULL, &type, (LPBYTE)value, &size);
    RegCloseKey(key);
    return result == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ) &&
        size > 1u && value[0] != '\0';
}

static BOOL set_and_read_registry_string(
    HKEY root, const char *key_name, const char *value_name,
    const char *expected)
{
    HKEY key = NULL;
    char value[32];
    DWORD disposition = 0u;
    DWORD type = 0u;
    DWORD size = sizeof(value);
    LONG result = RegCreateKeyExA(
        root, key_name, 0u, NULL, REG_OPTION_NON_VOLATILE,
        KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &key, &disposition);
    (void)disposition;
    if (result != ERROR_SUCCESS) return FALSE;
    result = RegSetValueExA(
        key, value_name, 0u, REG_SZ, (const BYTE *)expected,
        (DWORD)strlen(expected) + 1u);
    if (result == ERROR_SUCCESS) {
        result = RegQueryValueExA(
            key, value_name, NULL, &type, (LPBYTE)value, &size);
    }
    RegCloseKey(key);
    return result == ERROR_SUCCESS && type == REG_SZ &&
        strcmp(value, expected) == 0;
}

static BOOL activate_class(
    const CLSID *clsid, const IID *iid, const char *name)
{
    IUnknown *instance = NULL;
    HRESULT result = CoCreateInstance(
        clsid, NULL, CLSCTX_INPROC_SERVER, iid, (void **)&instance);
    printf(
        "MIEL_COM_ACTIVATION clsid=%s hresult=0x%08lx\n",
        name, (unsigned long)result);
    if (instance) IUnknown_Release(instance);
    return SUCCEEDED(result);
}

int main(int argc, char **argv)
{
    static const char *direct_sound_name =
        "{47D4D946-62E8-11CF-93BC-444553540000}";
    static const char *mmdevice_name =
        "{BCDE0395-E52F-467C-8E3D-C4579291692E}";
    HRESULT initialized;
    BOOL ok = TRUE;
    DWORD rpcss_timeout_ms = 30000u;

    if (argc != 3 || strcmp(argv[1], "--rpcss-timeout-ms") != 0 ||
        !parse_timeout_ms(argv[2], &rpcss_timeout_ms)) {
        fputs(
            "usage: wine-readiness-canary.exe "
            "--rpcss-timeout-ms 1000..120000\n",
            stderr);
        return 64;
    }

    puts("MIEL_FEX_WINE_CANARY_OK");
    fflush(stdout);
    if (!wait_for_rpcss(rpcss_timeout_ms)) {
        fputs("MIEL_RPCSS_STATE=FAILED\n", stderr);
        return 10;
    }
    puts("MIEL_RPCSS_STATE=RUNNING");
    if (!set_and_read_registry_string(
            HKEY_CURRENT_USER, "Software\\Wine\\Direct3D",
            "renderer", "gdi")) {
        fputs("MIEL_WINE_RENDERER=FAILED\n", stderr);
        ok = FALSE;
    } else {
        puts("MIEL_WINE_RENDERER=GDI");
    }
    if (!set_and_read_registry_string(
            HKEY_CURRENT_USER, "Software\\Wine\\X11 Driver",
            "Decorated", "N")) {
        fputs("MIEL_WINE_DECORATED=FAILED\n", stderr);
        ok = FALSE;
    } else {
        puts("MIEL_WINE_DECORATED=N");
    }
    if (!registry_class_exists(direct_sound_name)) ok = FALSE;
    else printf("MIEL_COM_REGISTRY clsid=%s\n", direct_sound_name);
    if (!registry_class_exists(mmdevice_name)) ok = FALSE;
    else printf("MIEL_COM_REGISTRY clsid=%s\n", mmdevice_name);

    initialized = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(initialized)) {
        fprintf(
            stderr, "MIEL_COM_INITIALIZATION hresult=0x%08lx\n",
            (unsigned long)initialized);
        return 11;
    }
    if (!activate_class(
            &CLSID_DirectSound, &IID_IDirectSound, direct_sound_name)) {
        ok = FALSE;
    }
    if (!activate_class(
            &CLSID_MMDeviceEnumerator, &IID_IMMDeviceEnumerator,
            mmdevice_name)) {
        ok = FALSE;
    }
    CoUninitialize();
    if (!ok) return 12;
    puts("MIEL_FEX_WINE_READINESS_OK");
    return 0;
}
