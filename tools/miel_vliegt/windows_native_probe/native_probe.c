#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define BP_MAX 4
#define THREAD_MAX 64
#define EXPECTED_EXE_SHA256 "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2"
#define MANAGER_TICK_SLOT 0x0044cc14u
#define MANAGER_RENDER_SLOT 0x0044cc10u
#define GT_CREATE_RETURN_RVA 0x21ddu
#define EXPECTED_TICK 0x0041d990u
#define EXPECTED_RENDER 0x0041dbc0u

typedef struct { uintptr_t address; BYTE original; int armed; const char *name; } Breakpoint;
typedef struct { DWORD id; uintptr_t rearm; uintptr_t create_out; int create_pending; } ThreadState;
static Breakpoint bp[BP_MAX];
static ThreadState threads[THREAD_MAX];
static HANDLE child;
static DWORD child_pid;
static unsigned long ticks, renders, create_calls, create_returns, create_success;
static unsigned long last_hr, last_device, pixel_samples, pixel_changes;
static unsigned long first_pixel, last_pixel, nonblack_pixels_max, captured_width, captured_height;
static int have_hr, have_pixel, gt_loaded, callsite_verified, manager_slots_verified, probe_error, process_alive_after_15s, window_present_after_15s, initial_breakpoint_seen;
static HWND game_window;
static unsigned long child_static_count, child_button_count, child_edit_count, process_cpu_ms;
static unsigned dialog_flags;
static const char *window_class = "none", *dialog_reason = "none";
static int select_hardware, no_debug, selection_decided, hardware_selection_attempted;
static int hardware_selection_sent, hardware_dialog_closed;
static HWND hardware_dialog;
static const char *hardware_selection_guard = "not_requested";
static char window_title_safe[65], button_labels_safe[2][21];
static unsigned long first_chance_av_count, fatal_exception_code, fatal_exception_rva;
static int have_fatal_exception, have_fatal_rva;
static const char *fatal_exception_module = "unknown";
static const char *fatal_access_type = "unavailable", *fatal_fault_category = "unavailable";

enum { REASON_MEDIA = 1, REASON_GRAPHICS = 2, REASON_MEMORY = 4,
       REASON_MISSING = 8, REASON_INSTALL = 16, REASON_ERROR = 32 };

static int remote_read(uintptr_t address, void *buffer, SIZE_T n)
{
    SIZE_T got = 0;
    return ReadProcessMemory(child, (LPCVOID)address, buffer, n, &got) && got == n;
}
static int remote_write(uintptr_t address, const void *buffer, SIZE_T n)
{
    DWORD old, ignored;
    SIZE_T done = 0;
    if (!VirtualProtectEx(child, (LPVOID)address, n, PAGE_EXECUTE_READWRITE, &old)) return 0;
    if (!WriteProcessMemory(child, (LPVOID)address, buffer, n, &done) || done != n) {
        VirtualProtectEx(child, (LPVOID)address, n, old, &ignored);
        return 0;
    }
    FlushInstructionCache(child, (LPCVOID)address, n);
    VirtualProtectEx(child, (LPVOID)address, n, old, &ignored);
    return 1;
}
static int arm(Breakpoint *b)
{
    const BYTE trap = 0xcc;
    if (!remote_write(b->address, &trap, 1)) return 0;
    b->armed = 1;
    return 1;
}
static int add_bp(uintptr_t address, const char *name)
{
    int i;
    if (!address) return 0;
    for (i = 0; i < BP_MAX; i++) {
        if (bp[i].address == address) return 1;
        if (!bp[i].address) {
            bp[i].address = address;
            bp[i].name = name;
            if (!remote_read(address, &bp[i].original, 1) || !arm(&bp[i])) {
                bp[i].address = 0;
                return 0;
            }
            return 1;
        }
    }
    return 0;
}
static ThreadState *thread_state(DWORD id)
{
    int i;
    ThreadState *empty = NULL;
    for (i = 0; i < THREAD_MAX; i++) {
        if (threads[i].id == id) return &threads[i];
        if (!threads[i].id && !empty) empty = &threads[i];
    }
    if (empty) empty->id = id;
    return empty;
}
static int is_target_hash(const char *path)
{
    BYTE buffer[16384], digest[32];
    DWORD count, size = sizeof digest;
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    char actual[65];
    int i, ok = 0;
    if (file == INVALID_HANDLE_VALUE) return 0;
    if (!CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) goto done;
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto done;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof buffer, &count, NULL)) goto done;
        if (!count) break;
        if (!CryptHashData(hash, buffer, count, 0)) goto done;
    }
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0) || size != 32) goto done;
    for (i = 0; i < 32; i++) sprintf(actual + 2*i, "%02x", digest[i]);
    actual[64] = 0;
    ok = strcmp(actual, EXPECTED_EXE_SHA256) == 0;
done:
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    CloseHandle(file);
    return ok;
}
static BOOL CALLBACK find_window(HWND window, LPARAM unused)
{
    DWORD pid = 0;
    RECT rect;
    (void)unused;
    GetWindowThreadProcessId(window, &pid);
    if (pid == child_pid && IsWindowVisible(window) && GetClientRect(window, &rect)
        && rect.right > 32 && rect.bottom > 32) {
        game_window = window;
        return FALSE;
    }
    return TRUE;
}
static void classify_text(char *value)
{
    char *p;
    for (p = value; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 'a' - 'A';
    if (strstr(value, "cd-rom") || strstr(value, "insert") || strstr(value, "schijf") ||
        strstr(value, "skiva") || strstr(value, "disc") || strstr(value, "disk")) dialog_flags |= REASON_MEDIA;
    if (strstr(value, "directx") || strstr(value, "direct3d") || strstr(value, "video") ||
        strstr(value, "display") || strstr(value, "graphic")) dialog_flags |= REASON_GRAPHICS;
    if (strstr(value, "memory") || strstr(value, "geheugen") || strstr(value, "minne")) dialog_flags |= REASON_MEMORY;
    if (strstr(value, "not found") || strstr(value, "missing") ||
        strstr(value, "niet vinden") || strstr(value, "saknas")) dialog_flags |= REASON_MISSING;
    if (strstr(value, "install") || strstr(value, "setup")) dialog_flags |= REASON_INSTALL;
    if (strstr(value, "error") || strstr(value, "fout") || strstr(value, "cannot") ||
        strstr(value, "kan inte") || strstr(value, "failed")) dialog_flags |= REASON_ERROR;
}
static void sanitize_label(char *destination, size_t capacity, const char *source)
{
    size_t i, length = strlen(source);
    if (length >= capacity) goto redacted;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)source[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              c == ' ' || c == '-')) goto redacted;
    }
    memcpy(destination, source, length + 1);
    return;
redacted:
    strcpy(destination, "REDACTED");
}
static void print_json_string(FILE *file, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    fputc('"', file);
    for (; *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', file); fputc(*p, file); }
        else if (*p < 0x20) fprintf(file, "\\u%04x", (unsigned)*p);
        else fputc(*p, file);
    }
    fputc('"', file);
}
static BOOL CALLBACK inspect_control(HWND control, LPARAM count_arg)
{
    char class_name[64], value[256];
    DWORD_PTR result;
    unsigned long *count = (unsigned long *)count_arg;
    if (++*count > 64) return FALSE;
    if (!GetClassNameA(control, class_name, sizeof class_name)) return TRUE;
    if (_stricmp(class_name, "Static") == 0) child_static_count++;
    else if (_stricmp(class_name, "Button") == 0) child_button_count++;
    else if (_stricmp(class_name, "Edit") == 0) child_edit_count++;
    else return TRUE;
    if (_stricmp(class_name, "Edit") == 0 || *count > 32) return TRUE;
    memset(value, 0, sizeof value);
    if (SendMessageTimeoutA(control, WM_GETTEXT, sizeof value, (LPARAM)value,
                            SMTO_ABORTIFHUNG | SMTO_BLOCK, 50, &result)) {
        value[sizeof value - 1] = 0;
        if (_stricmp(class_name, "Button") == 0 && child_button_count <= 2)
            sanitize_label(button_labels_safe[child_button_count - 1],
                           sizeof button_labels_safe[0], value);
        classify_text(value);
    }
    return TRUE;
}
static ULONGLONG cpu_ticks(void)
{
    FILETIME created, exited, kernel, user;
    ULARGE_INTEGER k, u;
    if (!GetProcessTimes(child, &created, &exited, &kernel, &user)) return 0;
    k.LowPart = kernel.dwLowDateTime; k.HighPart = kernel.dwHighDateTime;
    u.LowPart = user.dwLowDateTime; u.HighPart = user.dwHighDateTime;
    return k.QuadPart + u.QuadPart;
}
static void inspect_window(void)
{
    char name[64], title[256];
    unsigned long count = 0;
    if (!game_window || !IsWindow(game_window)) {
        game_window = NULL;
        EnumWindows(find_window, 0);
    }
    if (!game_window) return;
    child_static_count = child_button_count = child_edit_count = 0;
    window_title_safe[0] = 0;
    button_labels_safe[0][0] = button_labels_safe[1][0] = 0;
    dialog_flags = 0;
    dialog_reason = "none";
    if (GetClassNameA(game_window, name, sizeof name) && strcmp(name, "#32770") == 0)
        window_class = "#32770";
    else window_class = "other";
    memset(title, 0, sizeof title);
    GetWindowTextA(game_window, title, sizeof title);
    title[sizeof title - 1] = 0;
    sanitize_label(window_title_safe, sizeof window_title_safe, title);
    classify_text(title);
    EnumChildWindows(game_window, inspect_control, (LPARAM)&count);
    if (dialog_flags & REASON_MEDIA) dialog_reason = "media_prompt";
    else if (dialog_flags & REASON_GRAPHICS) dialog_reason = "graphics_error";
    else if (dialog_flags & REASON_MEMORY) dialog_reason = "memory_error";
    else if (dialog_flags & REASON_MISSING) dialog_reason = "missing_file";
    else if (dialog_flags & REASON_INSTALL) dialog_reason = "install_prompt";
    else if (dialog_flags & REASON_ERROR) dialog_reason = "generic_error";
    else if (strcmp(window_class, "#32770") == 0) dialog_reason = "unknown_dialog";
}
typedef struct {
    HWND hardware, software;
    unsigned total, edits, buttons, statics, hardware_count, software_count;
} HardwareControls;
static BOOL CALLBACK identify_hardware_controls(HWND control, LPARAM argument)
{
    HardwareControls *found = (HardwareControls *)argument;
    char name[64], label[32];
    DWORD_PTR delivered;
    if (++found->total > 16) return FALSE;
    if (!GetClassNameA(control, name, sizeof name)) return TRUE;
    if (_stricmp(name, "Edit") == 0) found->edits++;
    else if (_stricmp(name, "Static") == 0) found->statics++;
    else if (_stricmp(name, "Button") == 0) {
        found->buttons++;
        memset(label, 0, sizeof label);
        if (!SendMessageTimeoutA(control, WM_GETTEXT, sizeof label, (LPARAM)label,
                                 SMTO_ABORTIFHUNG | SMTO_BLOCK, 100, &delivered)) return TRUE;
        label[sizeof label - 1] = 0;
        if (_stricmp(label, "Hardware") == 0) {
            found->hardware_count++;
            found->hardware = control;
        } else if (_stricmp(label, "Software") == 0) {
            found->software_count++;
            found->software = control;
        }
    }
    return TRUE;
}
static void maybe_select_hardware(DWORD elapsed)
{
    HardwareControls controls;
    RECT rect;
    DWORD_PTR delivered;
    DWORD owner = 0;
    char name[64];
    if (!select_hardware || selection_decided || elapsed < 1500u) return;
    if (!game_window || !IsWindow(game_window)) {
        game_window = NULL;
        EnumWindows(find_window, 0);
    }
    if (!game_window) return;
    GetWindowThreadProcessId(game_window, &owner);
    if (owner != child_pid || !GetClassNameA(game_window, name, sizeof name) ||
        strcmp(name, "#32770") != 0) return;
    selection_decided = 1;
    hardware_selection_guard = "DIALOG_MISMATCH";
    if (!GetClientRect(game_window, &rect) || rect.right != 318 || rect.bottom != 140) return;
    memset(&controls, 0, sizeof controls);
    EnumChildWindows(game_window, identify_hardware_controls, (LPARAM)&controls);
    if (controls.total != 3 || controls.edits != 1 || controls.buttons != 2 ||
        controls.statics != 0 || controls.hardware_count != 1 || controls.software_count != 1) {
        hardware_selection_guard = "CONTROLS_MISMATCH";
        return;
    }
    if (!IsWindowVisible(controls.hardware) || !IsWindowEnabled(controls.hardware) ||
        !IsWindowVisible(controls.software) || !IsWindowEnabled(controls.software)) {
        hardware_selection_guard = "HARDWARE_UNAVAILABLE";
        return;
    }
    hardware_dialog = game_window;
    hardware_selection_attempted = 1;
    if (!SendMessageTimeoutA(controls.hardware, BM_CLICK, 0, 0,
                             SMTO_ABORTIFHUNG | SMTO_BLOCK, 1000, &delivered)) {
        hardware_selection_guard = "HARDWARE_CLICK_FAILED";
        return;
    }
    hardware_selection_sent = 1;
    hardware_selection_guard = "HARDWARE_CLICK_SENT";
}
static void sample_pixels(void)
{
    HDC source = NULL, memory = NULL;
    HBITMAP bitmap = NULL;
    HGDIOBJ prior = NULL;
    BITMAPINFO info;
    RECT rect;
    BYTE *pixels = NULL;
    uint32_t hash = 2166136261u;
    unsigned long nonblack = 0;
    int width, height, i;
    if (!game_window || !IsWindow(game_window)) {
        game_window = NULL;
        EnumWindows(find_window, 0);
    }
    if (!game_window || !GetClientRect(game_window, &rect)) return;
    width = rect.right - rect.left;
    height = rect.bottom - rect.top;
    if (width <= 0 || height <= 0 || width > 2048 || height > 2048) return;
    source = GetDC(game_window);
    if (!source) return;
    memory = CreateCompatibleDC(source);
    if (!memory) goto done;
    memset(&info, 0, sizeof info);
    info.bmiHeader.biSize = sizeof info.bmiHeader;
    info.bmiHeader.biWidth = width;
    info.bmiHeader.biHeight = -height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    bitmap = CreateDIBSection(source, &info, DIB_RGB_COLORS, (void **)&pixels, NULL, 0);
    if (!bitmap || !pixels) goto done;
    prior = SelectObject(memory, bitmap);
    if (!prior || prior == HGDI_ERROR) goto done;
    if (!BitBlt(memory, 0, 0, width, height, source, 0, 0, SRCCOPY)) goto done;
    for (i = 0; i < width * height; i++) {
        BYTE *p = pixels + 4 * i;
        int channel;
        if (p[0] || p[1] || p[2]) nonblack++;
        for (channel = 0; channel < 3; channel++)
            hash = (hash ^ p[channel]) * 16777619u;
    }
    if (nonblack > nonblack_pixels_max) nonblack_pixels_max = nonblack;
    captured_width = (unsigned long)width;
    captured_height = (unsigned long)height;
    if (have_pixel && hash != last_pixel) pixel_changes++;
    if (!have_pixel) first_pixel = hash;
    have_pixel = 1;
    last_pixel = hash;
    pixel_samples++;
done:
    if (prior && prior != HGDI_ERROR) SelectObject(memory, prior);
    if (bitmap) DeleteObject(bitmap);
    if (memory) DeleteDC(memory);
    ReleaseDC(game_window, source);
}
static int is_gt_module(const LOAD_DLL_DEBUG_INFO *dll)
{
    char path[1024];
    uintptr_t remote = 0;
    const char *base;
    HANDLE snapshot;
    MODULEENTRY32 entry;
    DWORD n;
    if (dll->hFile) {
        n = GetFinalPathNameByHandleA(dll->hFile, path, sizeof path, FILE_NAME_NORMALIZED);
        if (n > 0 && n < sizeof path) {
            base = strrchr(path, '\\');
            if (_stricmp(base ? base + 1 : path, "gtDirect3d.dll") == 0) return 1;
        }
    }
    if (dll->lpImageName && remote_read((uintptr_t)dll->lpImageName, &remote, 4) && remote) {
        size_t i;
        memset(path, 0, sizeof path);
        for (i = 0; i < sizeof path - 1; i++) {
            if (dll->fUnicode) {
                WCHAR c;
                if (!remote_read(remote + i * sizeof c, &c, sizeof c) || c > 127) break;
                path[i] = (char)c;
            } else if (!remote_read(remote + i, &path[i], 1)) break;
            if (!path[i]) break;
        }
        base = strrchr(path, '\\');
        if (_stricmp(base ? base + 1 : path, "gtDirect3d.dll") == 0) return 1;
    }
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, child_pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    memset(&entry, 0, sizeof entry);
    entry.dwSize = sizeof entry;
    if (Module32First(snapshot, &entry)) do {
        if ((uintptr_t)entry.modBaseAddr == (uintptr_t)dll->lpBaseOfDll &&
            _stricmp(entry.szModule, "gtDirect3d.dll") == 0) {
            CloseHandle(snapshot);
            return 1;
        }
    } while (Module32Next(snapshot, &entry));
    CloseHandle(snapshot);
    return 0;
}
static void observe_gt_callsite(uintptr_t module)
{
    BYTE bytes[6];
    uintptr_t ret = module + GT_CREATE_RETURN_RVA;
    uintptr_t call = 0;
    gt_loaded = 1;
    if (!remote_read(ret - 6, bytes, sizeof bytes)) return;
    /* Only accept indirect x86 CALL instructions ending at the known return RVA.
       FF /2 with disp8=0x10 is the IDirect3D7 vtable slot 4 call. */
    if (bytes[3] == 0xff && (bytes[4] & 0xf8) == 0x50 && bytes[5] == 0x10)
        call = ret - 3;
    else if (bytes[0] == 0xff && (bytes[1] & 0xf8) == 0x90 &&
             bytes[2] == 0x10 && bytes[3] == 0 && bytes[4] == 0 && bytes[5] == 0)
        call = ret - 6;
    if (call && add_bp(call, "create_enter") && add_bp(ret, "create_return"))
        callsite_verified = 1;
}
static void poll_gt_module(void)
{
    HANDLE snapshot;
    MODULEENTRY32 entry;
    if (gt_loaded) return;
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, child_pid);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    memset(&entry, 0, sizeof entry);
    entry.dwSize = sizeof entry;
    if (Module32First(snapshot, &entry)) do {
        if (_stricmp(entry.szModule, "gtDirect3d.dll") == 0) {
            gt_loaded = 1;
            break;
        }
    } while (Module32Next(snapshot, &entry));
    CloseHandle(snapshot);
}
static void classify_exception_module(uintptr_t address)
{
    HANDLE snapshot;
    MODULEENTRY32 entry;
    char windows[512];
    DWORD windows_length = GetWindowsDirectoryA(windows, sizeof windows);
    int attempt;
    for (attempt = 0; attempt < 3; attempt++) {
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, child_pid);
        if (snapshot != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
    }
    if (snapshot == INVALID_HANDLE_VALUE) return;
    memset(&entry, 0, sizeof entry);
    entry.dwSize = sizeof entry;
    if (Module32First(snapshot, &entry)) do {
        uintptr_t base = (uintptr_t)entry.modBaseAddr;
        if (address < base || address - base >= entry.modBaseSize) continue;
        if (_stricmp(entry.szModule, "MulleMeck.exe") == 0)
            fatal_exception_module = "MulleMeck.exe";
        else if (_stricmp(entry.szModule, "gtDirect3d.dll") == 0)
            fatal_exception_module = "gtDirect3d.dll";
        else if (_stricmp(entry.szModule, "Cc.dll") == 0)
            fatal_exception_module = "Cc.dll";
        else if (windows_length > 0 && windows_length < sizeof windows &&
                 _strnicmp(entry.szExePath, windows, windows_length) == 0 &&
                 (entry.szExePath[windows_length] == '\\' || entry.szExePath[windows_length] == '/'))
            fatal_exception_module = "system";
        if (strcmp(fatal_exception_module, "unknown") != 0) {
            fatal_exception_rva = (unsigned long)(address - base);
            have_fatal_rva = 1;
        }
        break;
    } while (Module32Next(snapshot, &entry));
    CloseHandle(snapshot);
}
static void record_fatal_exception(const EXCEPTION_RECORD *exception)
{
    uintptr_t address;
    MEMORY_BASIC_INFORMATION memory;
    fatal_exception_code = exception->ExceptionCode;
    have_fatal_exception = 1;
    address = (uintptr_t)exception->ExceptionAddress;
    classify_exception_module(address);
    if ((exception->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
         exception->ExceptionCode != EXCEPTION_IN_PAGE_ERROR) ||
        exception->NumberParameters < 2) return;
    if (exception->ExceptionInformation[0] == 0) fatal_access_type = "read";
    else if (exception->ExceptionInformation[0] == 1) fatal_access_type = "write";
    else if (exception->ExceptionInformation[0] == 8) fatal_access_type = "execute";
    else fatal_access_type = "other";
    address = (uintptr_t)exception->ExceptionInformation[1];
    if (address == 0) fatal_fault_category = "null";
    else if (address < 0x10000u) fatal_fault_category = "near_null";
    else if (!VirtualQueryEx(child, (LPCVOID)address, &memory, sizeof memory) ||
             memory.State != MEM_COMMIT) fatal_fault_category = "unmapped";
    else if (memory.Type == MEM_IMAGE) fatal_fault_category = "image";
    else if (memory.Type == MEM_PRIVATE) fatal_fault_category = "private";
    else if (memory.Type == MEM_MAPPED) fatal_fault_category = "mapped";
    else fatal_fault_category = "other";
}
static void observe_debug_event(const DEBUG_EVENT *event, DWORD *continue_status)
{
    if (event->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
        uintptr_t tick = 0, render = 0;
        if (event->u.CreateProcessInfo.hFile) CloseHandle(event->u.CreateProcessInfo.hFile);
        if (remote_read(MANAGER_TICK_SLOT, &tick, 4) && remote_read(MANAGER_RENDER_SLOT, &render, 4) &&
            tick == EXPECTED_TICK && render == EXPECTED_RENDER) {
            manager_slots_verified = 1;
            if (!add_bp(tick, "manager_tick") || !add_bp(render, "manager_render")) probe_error = 1;
        } else probe_error = 1;
        if (event->u.CreateProcessInfo.hThread) CloseHandle(event->u.CreateProcessInfo.hThread);
    } else if (event->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
        HANDLE file = event->u.LoadDll.hFile;
        if (is_gt_module(&event->u.LoadDll))
            observe_gt_callsite((uintptr_t)event->u.LoadDll.lpBaseOfDll);
        if (file) CloseHandle(file);
    } else if (event->dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
        if (event->u.CreateThread.hThread) CloseHandle(event->u.CreateThread.hThread);
    } else if (event->dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
        ThreadState *state = thread_state(event->dwThreadId);
        if (state) memset(state, 0, sizeof *state);
    } else if (event->dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
        const EXCEPTION_DEBUG_INFO *ex = &event->u.Exception;
        DWORD code = ex->ExceptionRecord.ExceptionCode;
        ThreadState *state = thread_state(event->dwThreadId);
        HANDLE handle;
        CONTEXT context;
        int i;
        *continue_status = DBG_EXCEPTION_NOT_HANDLED;
        if (code == EXCEPTION_ACCESS_VIOLATION && ex->dwFirstChance)
            first_chance_av_count++;
        if (!ex->dwFirstChance && !have_fatal_exception)
            record_fatal_exception(&ex->ExceptionRecord);
        if (!state || (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP)) return;
        handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event->dwThreadId);
        if (!handle) return;
        memset(&context, 0, sizeof context);
        context.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(handle, &context)) { CloseHandle(handle); return; }
        if (code == EXCEPTION_SINGLE_STEP && state->rearm) {
            for (i = 0; i < BP_MAX; i++) if (bp[i].address == state->rearm) {
                if (!arm(&bp[i])) probe_error = 1;
                break;
            }
            state->rearm = 0;
            context.EFlags &= ~0x100u;
            if (!SetThreadContext(handle, &context)) probe_error = 1;
            *continue_status = DBG_CONTINUE;
        } else if (code == EXCEPTION_BREAKPOINT) {
            uintptr_t at = (uintptr_t)ex->ExceptionRecord.ExceptionAddress;
            for (i = 0; i < BP_MAX; i++) if (bp[i].armed && bp[i].address == at) break;
            if (i < BP_MAX) {
                Breakpoint *b = &bp[i];
                if (strcmp(b->name, "manager_tick") == 0) ticks++;
                else if (strcmp(b->name, "manager_render") == 0) renders++;
                else if (strcmp(b->name, "create_enter") == 0) {
                    DWORD out = 0;
                    if (remote_read((uintptr_t)context.Esp + 12, &out, 4)) {
                        state->create_out = out;
                        state->create_pending = 1;
                        create_calls++;
                    }
                } else if (strcmp(b->name, "create_return") == 0 && state->create_pending) {
                    DWORD device = 0;
                    last_hr = context.Eax;
                    last_device = 0;
                    have_hr = 1;
                    create_returns++;
                    if (remote_read(state->create_out, &device, 4)) {
                        last_device = device;
                        if ((LONG)last_hr >= 0 && device) create_success++;
                    }
                    state->create_pending = 0;
                }
                if (!remote_write(b->address, &b->original, 1)) probe_error = 1;
                b->armed = 0;
                context.Eip = (DWORD)b->address;
                context.EFlags |= 0x100u;
                state->rearm = b->address;
                if (!SetThreadContext(handle, &context)) probe_error = 1;
                *continue_status = DBG_CONTINUE;
            } else if (!initial_breakpoint_seen && ex->dwFirstChance) {
                /* Windows sends one initial breakpoint before application entry. */
                initial_breakpoint_seen = 1;
                *continue_status = DBG_CONTINUE;
            }
        }
        CloseHandle(handle);
    }
}
int main(int argc, char **argv)
{
    STARTUPINFOA start;
    PROCESS_INFORMATION process;
    DEBUG_EVENT event;
    char command[2048], directory[1024], *slash;
    DWORD started, duration = 20, last_sample = 0, status, exit_code = 0;
    ULONGLONG cpu_start, cpu_end;
    int alive = 1, duration_set = 0, arg;
    FILE *log;
    if (argc < 3 || argc > 6) { fprintf(stderr, "usage: native_probe.exe MulleMeck.exe result.json [seconds] [--select-hardware] [--no-debug]\n"); return 2; }
    for (arg = 3; arg < argc; arg++) {
        if (strcmp(argv[arg], "--select-hardware") == 0 && !select_hardware) {
            select_hardware = 1;
            hardware_selection_guard = "WAITING_FOR_DIALOG";
        } else if (strcmp(argv[arg], "--no-debug") == 0 && !no_debug) {
            no_debug = 1;
        } else if (!duration_set) {
            char *end;
            unsigned long value = strtoul(argv[arg], &end, 10);
            if (*end || value < 1 || value > 120) return 2;
            duration = (DWORD)value;
            duration_set = 1;
        } else return 2;
    }
    if (!is_target_hash(argv[1])) { fprintf(stderr, "MulleMeck.exe SHA256 mismatch or unreadable\n"); return 3; }
    if (strlen(argv[1]) + 3 >= sizeof command || strlen(argv[1]) >= sizeof directory) return 2;
    strcpy(directory, argv[1]);
    slash = strrchr(directory, '\\');
    if (!slash) slash = strrchr(directory, '/');
    if (!slash) return 2;
    *slash = 0;
    sprintf(command, "\"%s\"", argv[1]);
    memset(&start, 0, sizeof start);
    memset(&process, 0, sizeof process);
    start.cb = sizeof start;
    if (!CreateProcessA(argv[1], command, NULL, NULL, FALSE,
                        CREATE_NEW_PROCESS_GROUP | (no_debug ? 0 : DEBUG_ONLY_THIS_PROCESS),
                        NULL, directory, &start, &process)) {
        fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
        return 4;
    }
    child = process.hProcess;
    child_pid = process.dwProcessId;
    CloseHandle(process.hThread);
    cpu_start = cpu_ticks();
    started = GetTickCount();
    while (alive && GetTickCount() - started < duration * 1000u) {
        DWORD elapsed = GetTickCount() - started;
        if (elapsed >= 15000u) {
            process_alive_after_15s = 1;
            if (game_window && IsWindow(game_window)) window_present_after_15s = 1;
        }
        if (hardware_selection_sent && hardware_dialog &&
            (!IsWindow(hardware_dialog) || !IsWindowVisible(hardware_dialog)))
            hardware_dialog_closed = 1;
        maybe_select_hardware(elapsed);
        if (elapsed / 500u != last_sample) {
            last_sample = elapsed / 500u;
            sample_pixels();
            if (no_debug) poll_gt_module();
        }
        if (no_debug) {
            DWORD wait_result = WaitForSingleObject(child, 100);
            if (wait_result == WAIT_OBJECT_0) {
                alive = 0;
                if (!GetExitCodeProcess(child, &exit_code)) probe_error = 1;
            } else if (wait_result != WAIT_TIMEOUT) probe_error = 1;
            if (probe_error) break;
            continue;
        }
        if (!WaitForDebugEvent(&event, 100)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) continue;
            probe_error = 1;
            break;
        }
        status = DBG_CONTINUE;
        observe_debug_event(&event, &status);
        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) { alive = 0; exit_code = event.u.ExitProcess.dwExitCode; }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status)) {
            probe_error = 1;
            break;
        }
        if (probe_error) break;
    }
    if (hardware_selection_sent && hardware_dialog &&
        (!IsWindow(hardware_dialog) || !IsWindowVisible(hardware_dialog)))
        hardware_dialog_closed = 1;
    inspect_window();
    cpu_end = cpu_ticks();
    if (cpu_end >= cpu_start) process_cpu_ms = (unsigned long)((cpu_end - cpu_start) / 10000u);
    if (alive) { TerminateProcess(child, 0); WaitForSingleObject(child, 5000); }
    CloseHandle(child);
    log = fopen(argv[2], "wb");
    if (!log) { fprintf(stderr, "result log open failed: %lu\n", GetLastError()); return 5; }
    fprintf(log,
        "{\"schema\":\"native-flight-probe-v1\",\"exe_sha256\":\"%s\","
        "\"debugger_attached\":%s,\"gt_loaded\":%s,\"create_callsite_verified\":%s,\"manager_slots_verified\":%s,\"create_calls\":%lu,"
        "\"create_returns\":%lu,\"create_success\":%lu,\"create_hr\":",
        EXPECTED_EXE_SHA256, no_debug ? "false" : "true", gt_loaded ? "true" : "false",
        callsite_verified ? "true" : "false",
        manager_slots_verified ? "true" : "false", create_calls, create_returns, create_success);
    if (have_hr) fprintf(log, "\"0x%08lX\"", last_hr); else fputs("null", log);
    fprintf(log,
        ",\"device_nonnull\":%s,\"manager_ticks\":%lu,\"manager_renders\":%lu,"
        "\"pixel_samples\":%lu,\"pixel_changes\":%lu,\"nonblack_pixels_max\":%lu,"
        "\"captured_width\":%lu,\"captured_height\":%lu,\"window_present\":%s,"
        "\"window_class\":\"%s\",\"child_static_count\":%lu,\"child_button_count\":%lu,"
        "\"child_edit_count\":%lu,\"dialog_reason\":\"%s\",\"process_cpu_ms\":%lu,"
        "\"hardware_selection_requested\":%s,\"hardware_selection_attempted\":%s,"
        "\"hardware_selection_sent\":%s,\"hardware_dialog_closed\":%s,"
        "\"hardware_selection_guard\":\"%s\","
        "\"first_pixel_hash\":\"%08lX\",\"last_pixel_hash\":\"%08lX\","
        "\"child_exited\":%s,\"child_exit_code\":%lu,\"process_alive_after_15s\":%s,\"probe_error\":%s,"
        "\"first_chance_av_count\":%lu,",
        last_device ? "true" : "false", ticks, renders, pixel_samples, pixel_changes,
        nonblack_pixels_max, captured_width, captured_height, window_present_after_15s ? "true" : "false",
        window_class, child_static_count, child_button_count, child_edit_count, dialog_reason, process_cpu_ms,
        select_hardware ? "true" : "false", hardware_selection_attempted ? "true" : "false",
        hardware_selection_sent ? "true" : "false", hardware_dialog_closed ? "true" : "false",
        hardware_selection_guard,
        first_pixel, last_pixel, alive ? "false" : "true", exit_code,
        process_alive_after_15s ? "true" : "false", probe_error ? "true" : "false",
        first_chance_av_count);
    fputs("\"fatal_exception_code\":", log);
    if (have_fatal_exception) fprintf(log, "\"0x%08lX\"", fatal_exception_code);
    else fputs("null", log);
    fputs(",\"fatal_exception_module\":", log);
    print_json_string(log, fatal_exception_module);
    fputs(",\"fatal_exception_rva\":", log);
    if (have_fatal_rva) fprintf(log, "\"0x%08lX\"", fatal_exception_rva);
    else fputs("null", log);
    fputs(",\"fatal_access_type\":", log);
    print_json_string(log, fatal_access_type);
    fputs(",\"fatal_fault_category\":", log);
    print_json_string(log, fatal_fault_category);
    fputs(",\"window_title_safe\":", log);
    print_json_string(log, window_title_safe);
    fputs(",\"button_labels_safe\":[", log);
    print_json_string(log, button_labels_safe[0]);
    fputc(',', log);
    print_json_string(log, button_labels_safe[1]);
    fputs("]}\n", log);
    fclose(log);
    return probe_error ? 6 : 0;
}
