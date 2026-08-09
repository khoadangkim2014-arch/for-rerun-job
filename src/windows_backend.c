#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <dbghelp.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <strsafe.h>
#include <winhttp.h>
#include <winternl.h>

#include <stdarg.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "pe_scan.h"
#include "uwd.h"

#define UWD_MIN_WINDOWS_BUILD 19041U
#define UWD_PATH_CAP          32768U
#define UWD_STATE_VERSION     3U
#define UWD_RUN_KEY           L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define UWD_RUN_VALUE         L"UniversalWatermarkDisabler"
#ifndef SYMFLAG_FUNCTION
#define SYMFLAG_FUNCTION      0x00000800U
#endif
#ifndef SYMFLAG_PUBLIC_CODE
#define SYMFLAG_PUBLIC_CODE   0x00400000U
#endif
#define UWD_SYMTAG_FUNCTION      5U
#define UWD_SYMTAG_PUBLIC_SYMBOL 10U

typedef struct UwdContext {
    DWORD os_build;
    DWORD explorer_pid;
    DWORD explorer_session_id;
    uint64_t explorer_creation_time;
    HANDLE explorer;
    uintptr_t shell32_base;
    DWORD shell32_size;
    wchar_t shell32_path[UWD_PATH_CAP];
    unsigned char *image;
    size_t image_size;
    UwdPeIdentity identity;
    UwdPeIdentity loaded_identity;
    unsigned char image_sha256[32];
    USHORT target_machine;
    int dynamic_code_policy_known;
    int dynamic_code_blocked;
} UwdContext;

#pragma pack(push, 1)
typedef struct UwdPatchState {
    char magic[8];
    uint32_t version;
    uint32_t explorer_pid;
    uint32_t explorer_session_id;
    uint64_t explorer_creation_time;
    uint64_t shell32_base;
    uint16_t machine;
    uint16_t patch_length;
    uint32_t image_timestamp;
    uint32_t image_size;
    uint32_t rva;
    uint32_t original_protection;
    unsigned char image_sha256[32];
    unsigned char original[8];
    unsigned char patch[8];
    unsigned char state_sha256[32];
} UwdPatchState;
#pragma pack(pop)

typedef LONG (WINAPI *RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
typedef BOOL (WINAPI *IsWow64Process2Fn)(HANDLE, USHORT *, USHORT *);

static int is_executable_protection(DWORD protection);
static int is_writable_executable_protection(DWORD protection);

static void print_message(const UwdOptions *options, const wchar_t *format, ...)
{
    va_list args;
    if (options != NULL && options->quiet) {
        return;
    }
    va_start(args, format);
    vfwprintf(stdout, format, args);
    va_end(args);
    fputwc(L'\n', stdout);
}

static void print_verbose(const UwdOptions *options, const wchar_t *format, ...)
{
    va_list args;
    if (options == NULL || options->quiet) {
        return;
    }
    va_start(args, format);
    vfwprintf(stdout, format, args);
    va_end(args);
    fputwc(L'\n', stdout);
}

static void print_win32_error(const wchar_t *operation, DWORD error)
{
    wchar_t detail[512];
    DWORD count = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        0,
        detail,
        (DWORD)(sizeof(detail) / sizeof(detail[0])),
        NULL);

    if (count == 0) {
        fwprintf(stderr, L"Error: %ls failed (Win32 error %lu).\n", operation, error);
        return;
    }
    while (count != 0 && (detail[count - 1] == L'\r' || detail[count - 1] == L'\n')) {
        detail[--count] = L'\0';
    }
    fwprintf(stderr, L"Error: %ls failed: %ls (%lu).\n", operation, detail, error);
}

static int path_join(
    wchar_t *destination,
    size_t destination_count,
    const wchar_t *directory,
    const wchar_t *name)
{
    HRESULT hr = StringCchPrintfW(destination, destination_count, L"%ls\\%ls", directory, name);
    return SUCCEEDED(hr) ? 0 : -1;
}

static int get_data_directory(
    wchar_t *buffer,
    size_t buffer_count,
    int create)
{
    PWSTR local_app_data = NULL;
    HRESULT hr;
    DWORD error;

    if (buffer == NULL || buffer_count == 0) {
        return -1;
    }

    hr = SHGetKnownFolderPath(
        &FOLDERID_LocalAppData,
        create ? KF_FLAG_CREATE : KF_FLAG_DEFAULT,
        NULL,
        &local_app_data);
    if (FAILED(hr)) {
        return -1;
    }

    hr = StringCchPrintfW(
        buffer,
        buffer_count,
        L"%ls\\UniversalWatermarkDisabler",
        local_app_data);
    CoTaskMemFree(local_app_data);
    if (FAILED(hr)) {
        return -1;
    }

    if (!create || CreateDirectoryW(buffer, NULL)) {
        return 0;
    }
    error = GetLastError();
    return error == ERROR_ALREADY_EXISTS ? 0 : -1;
}

int uwd_get_data_directory(wchar_t *buffer, size_t buffer_count)
{
    return get_data_directory(buffer, buffer_count, 1);
}

static int query_os_build(DWORD *build)
{
    HMODULE ntdll;
    FARPROC procedure;
    RtlGetVersionFn rtl_get_version;
    RTL_OSVERSIONINFOW version;
    LONG status;

    if (build == NULL) {
        return -1;
    }
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return -1;
    }
    procedure = GetProcAddress(ntdll, "RtlGetVersion");
    if (procedure == NULL || sizeof(procedure) != sizeof(rtl_get_version)) {
        return -1;
    }
    memcpy(&rtl_get_version, &procedure, sizeof(rtl_get_version));

    ZeroMemory(&version, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    status = rtl_get_version(&version);
    if (status < 0 || version.dwMajorVersion != 10) {
        return -1;
    }
    *build = version.dwBuildNumber;
    return 0;
}

static USHORT compiled_machine(void)
{
#if defined(_M_X64) || defined(__x86_64__)
    return IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_ARM64) || defined(__aarch64__)
    return IMAGE_FILE_MACHINE_ARM64;
#else
    return IMAGE_FILE_MACHINE_UNKNOWN;
#endif
}

static const wchar_t *machine_name(USHORT machine)
{
    switch (machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        return L"x64";
    case IMAGE_FILE_MACHINE_ARM64:
        return L"ARM64";
    case IMAGE_FILE_MACHINE_I386:
        return L"x86";
    default:
        return L"unknown";
    }
}

static int query_process_machine(HANDLE process, USHORT *machine)
{
    HMODULE kernel32;
    FARPROC procedure;
    IsWow64Process2Fn is_wow64_process2;
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;

    if (machine == NULL) {
        return -1;
    }
    kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 == NULL) {
        return -1;
    }
    procedure = GetProcAddress(kernel32, "IsWow64Process2");
    if (procedure == NULL || sizeof(procedure) != sizeof(is_wow64_process2)) {
        return -1;
    }
    memcpy(&is_wow64_process2, &procedure, sizeof(is_wow64_process2));
    if (
        !is_wow64_process2(process, &process_machine, &native_machine)) {
        return -1;
    }
    *machine = process_machine == IMAGE_FILE_MACHINE_UNKNOWN ? native_machine : process_machine;
    return 0;
}

static int wait_for_explorer_pid(unsigned int wait_seconds, DWORD *pid)
{
    unsigned int elapsed;

    if (pid == NULL) {
        return -1;
    }
    for (elapsed = 0; elapsed <= wait_seconds; ++elapsed) {
        HWND shell = GetShellWindow();
        DWORD candidate = 0;
        if (shell == NULL) {
            shell = FindWindowW(L"Shell_TrayWnd", NULL);
        }
        if (shell != NULL) {
            (void)GetWindowThreadProcessId(shell, &candidate);
            if (candidate != 0) {
                *pid = candidate;
                return 0;
            }
        }
        if (elapsed != wait_seconds) {
            Sleep(1000);
        }
    }
    return -1;
}

static int find_shell32_module(UwdContext *context)
{
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32W entry;
    DWORD error = ERROR_SUCCESS;
    int attempt;

    for (attempt = 0; attempt < 5; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            context->explorer_pid);
        if (snapshot != INVALID_HANDLE_VALUE) {
            break;
        }
        error = GetLastError();
        if (error != ERROR_BAD_LENGTH) {
            return -1;
        }
    }
    if (snapshot == INVALID_HANDLE_VALUE) {
        SetLastError(error);
        return -1;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) {
        error = GetLastError();
        CloseHandle(snapshot);
        SetLastError(error);
        return -1;
    }

    do {
        if (_wcsicmp(entry.szModule, L"shell32.dll") == 0) {
            context->shell32_base = (uintptr_t)entry.modBaseAddr;
            context->shell32_size = entry.modBaseSize;
            if (FAILED(StringCchCopyW(
                    context->shell32_path,
                    UWD_PATH_CAP,
                    entry.szExePath))) {
                CloseHandle(snapshot);
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return -1;
            }
            CloseHandle(snapshot);
            return 0;
        }
    } while (Module32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    SetLastError(ERROR_MOD_NOT_FOUND);
    return -1;
}

static int read_remote_pe_identity(
    const UwdContext *context,
    UwdPeIdentity *identity)
{
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS64 nt_headers;
    SIZE_T received = 0;
    uintptr_t nt_address;

    if (context == NULL || identity == NULL ||
        context->shell32_size < sizeof(dos_header) ||
        context->shell32_size < sizeof(nt_headers)) {
        return -1;
    }
    ZeroMemory(identity, sizeof(*identity));
    if (!ReadProcessMemory(
            context->explorer,
            (LPCVOID)context->shell32_base,
            &dos_header,
            sizeof(dos_header),
            &received) ||
        received != sizeof(dos_header) ||
        dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
        dos_header.e_lfanew <= 0 ||
        (size_t)dos_header.e_lfanew >
            (size_t)context->shell32_size - sizeof(nt_headers) ||
        context->shell32_base >
            UINTPTR_MAX - (uintptr_t)dos_header.e_lfanew) {
        return -1;
    }
    nt_address = context->shell32_base + (uintptr_t)dos_header.e_lfanew;
    received = 0;
    if (!ReadProcessMemory(
            context->explorer,
            (LPCVOID)nt_address,
            &nt_headers,
            sizeof(nt_headers),
            &received) ||
        received != sizeof(nt_headers) ||
        nt_headers.Signature != IMAGE_NT_SIGNATURE ||
        nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return -1;
    }
    identity->machine = nt_headers.FileHeader.Machine;
    identity->timestamp = nt_headers.FileHeader.TimeDateStamp;
    identity->size_of_image = nt_headers.OptionalHeader.SizeOfImage;
    return 0;
}

static int read_entire_file(
    const wchar_t *path,
    unsigned char **data,
    size_t *data_size)
{
    HANDLE file;
    LARGE_INTEGER size;
    unsigned char *buffer;
    size_t offset = 0;

    if (data == NULL || data_size == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 128LL * 1024LL * 1024LL) {
        DWORD error = GetLastError();
        if (error == ERROR_SUCCESS) {
            error = ERROR_FILE_TOO_LARGE;
        }
        CloseHandle(file);
        SetLastError(error);
        return -1;
    }

    buffer = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size.QuadPart);
    if (buffer == NULL) {
        CloseHandle(file);
        SetLastError(ERROR_OUTOFMEMORY);
        return -1;
    }

    while (offset < (size_t)size.QuadPart) {
        DWORD chunk = (DWORD)(((size_t)size.QuadPart - offset) > 1024U * 1024U
            ? 1024U * 1024U
            : ((size_t)size.QuadPart - offset));
        DWORD received = 0;
        if (!ReadFile(file, buffer + offset, chunk, &received, NULL) || received == 0) {
            DWORD error = GetLastError();
            HeapFree(GetProcessHeap(), 0, buffer);
            CloseHandle(file);
            SetLastError(error == ERROR_SUCCESS ? ERROR_HANDLE_EOF : error);
            return -1;
        }
        offset += received;
    }

    CloseHandle(file);
    *data = buffer;
    *data_size = (size_t)size.QuadPart;
    return 0;
}

static int sha256_buffer(
    const unsigned char *data,
    size_t data_size,
    unsigned char digest[32])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR hash_object = NULL;
    ULONG object_size = 0;
    ULONG hash_size = 0;
    ULONG received = 0;
    NTSTATUS status;
    int result = -1;

    if (data == NULL || data_size == 0 || data_size > ULONG_MAX) {
        return -1;
    }
    status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0);
    if (status < 0) {
        goto cleanup;
    }
    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&object_size,
        sizeof(object_size),
        &received,
        0);
    if (status < 0 || received != sizeof(object_size) || object_size == 0) {
        goto cleanup;
    }
    status = BCryptGetProperty(
        algorithm,
        BCRYPT_HASH_LENGTH,
        (PUCHAR)&hash_size,
        sizeof(hash_size),
        &received,
        0);
    if (status < 0 || received != sizeof(hash_size) || hash_size != 32) {
        goto cleanup;
    }
    hash_object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, object_size);
    if (hash_object == NULL) {
        goto cleanup;
    }
    status = BCryptCreateHash(
        algorithm,
        &hash,
        hash_object,
        object_size,
        NULL,
        0,
        0);
    if (status < 0) {
        goto cleanup;
    }
    status = BCryptHashData(hash, (PUCHAR)data, (ULONG)data_size, 0);
    if (status < 0) {
        goto cleanup;
    }
    status = BCryptFinishHash(hash, digest, 32, 0);
    if (status < 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (hash != NULL) {
        (void)BCryptDestroyHash(hash);
    }
    if (hash_object != NULL) {
        HeapFree(GetProcessHeap(), 0, hash_object);
    }
    if (algorithm != NULL) {
        (void)BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    return result;
}

static void close_context(UwdContext *context)
{
    if (context->image != NULL) {
        HeapFree(GetProcessHeap(), 0, context->image);
        context->image = NULL;
    }
    if (context->explorer != NULL) {
        CloseHandle(context->explorer);
        context->explorer = NULL;
    }
}

static int verify_explorer_image(HANDLE process)
{
    wchar_t actual[UWD_PATH_CAP];
    wchar_t windows_directory[UWD_PATH_CAP];
    wchar_t expected[UWD_PATH_CAP];
    DWORD actual_count = UWD_PATH_CAP;
    UINT windows_count;

    if (!QueryFullProcessImageNameW(process, 0, actual, &actual_count) ||
        actual_count == 0 || actual_count >= UWD_PATH_CAP) {
        return -1;
    }
    windows_count = GetWindowsDirectoryW(windows_directory, UWD_PATH_CAP);
    if (windows_count == 0 || windows_count >= UWD_PATH_CAP ||
        FAILED(StringCchPrintfW(
            expected,
            UWD_PATH_CAP,
            L"%ls\\explorer.exe",
            windows_directory))) {
        return -1;
    }
    if (_wcsicmp(actual, expected) != 0) {
        SetLastError(ERROR_INVALID_NAME);
        return -1;
    }
    return 0;
}

static int open_context(
    UwdContext *context,
    int require_write,
    int require_disk_match,
    const UwdOptions *options)
{
    DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic_code;
    FILETIME creation_time;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    ULARGE_INTEGER creation_value;
    DWORD current_session_id;

    ZeroMemory(context, sizeof(*context));
    if (query_os_build(&context->os_build) != 0) {
        fwprintf(stderr, L"Error: this program requires Windows 10 or Windows 11.\n");
        return -1;
    }
    if (context->os_build < UWD_MIN_WINDOWS_BUILD) {
        fwprintf(
            stderr,
            L"Error: Windows build %lu is too old; build %u or newer is required.\n",
            context->os_build,
            UWD_MIN_WINDOWS_BUILD);
        return -1;
    }
    if (compiled_machine() == IMAGE_FILE_MACHINE_UNKNOWN || sizeof(void *) != 8) {
        fwprintf(stderr, L"Error: use the native x64 or ARM64 build.\n");
        return -1;
    }
    if (wait_for_explorer_pid(options != NULL ? options->wait_seconds : 0, &context->explorer_pid) != 0) {
        fwprintf(stderr, L"Error: Explorer is not running in the current interactive session.\n");
        return -1;
    }
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &current_session_id) ||
        !ProcessIdToSessionId(context->explorer_pid, &context->explorer_session_id) ||
        context->explorer_session_id != current_session_id) {
        fwprintf(stderr, L"Error: Explorer is not in this program's interactive session.\n");
        return -1;
    }

    if (require_write) {
        access |= PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    }
    context->explorer = OpenProcess(access, FALSE, context->explorer_pid);
    if (context->explorer == NULL) {
        print_win32_error(L"OpenProcess(explorer.exe)", GetLastError());
        return -1;
    }
    if (verify_explorer_image(context->explorer) != 0) {
        fwprintf(
            stderr,
            L"Error: the desktop shell owner is not the canonical Windows explorer.exe.\n");
        close_context(context);
        return -1;
    }
    if (!GetProcessTimes(
            context->explorer,
            &creation_time,
            &exit_time,
            &kernel_time,
            &user_time)) {
        print_win32_error(L"GetProcessTimes(explorer.exe)", GetLastError());
        close_context(context);
        return -1;
    }
    creation_value.LowPart = creation_time.dwLowDateTime;
    creation_value.HighPart = creation_time.dwHighDateTime;
    context->explorer_creation_time = creation_value.QuadPart;

    if (query_process_machine(context->explorer, &context->target_machine) != 0) {
        print_win32_error(L"IsWow64Process2", GetLastError());
        close_context(context);
        return -1;
    }
    if (context->target_machine != compiled_machine()) {
        fwprintf(
            stderr,
            L"Error: the %ls executable cannot patch a %ls Explorer process.\n",
            machine_name(compiled_machine()),
            machine_name(context->target_machine));
        close_context(context);
        return -1;
    }

    if (find_shell32_module(context) != 0) {
        print_win32_error(L"locating shell32.dll in explorer.exe", GetLastError());
        close_context(context);
        return -1;
    }
    if (read_remote_pe_identity(context, &context->loaded_identity) != 0 ||
        context->loaded_identity.machine != context->target_machine ||
        context->loaded_identity.size_of_image != context->shell32_size) {
        fwprintf(stderr, L"Error: the loaded shell32.dll headers are invalid or inconsistent.\n");
        close_context(context);
        return -1;
    }
    if (!require_disk_match) {
        goto query_mitigation;
    }
    if (read_entire_file(context->shell32_path, &context->image, &context->image_size) != 0) {
        print_win32_error(L"reading shell32.dll", GetLastError());
        close_context(context);
        return -1;
    }
    if (uwd_pe_identity(
            context->image,
            context->image_size,
            &context->identity,
            NULL,
            0) != 0) {
        fwprintf(stderr, L"Error: shell32.dll is not a valid supported PE image.\n");
        close_context(context);
        return -1;
    }
    if (sha256_buffer(
            context->image,
            context->image_size,
            context->image_sha256) != 0) {
        fwprintf(stderr, L"Error: could not hash shell32.dll with SHA-256.\n");
        close_context(context);
        return -1;
    }
    if (context->identity.machine != context->target_machine ||
        context->identity.size_of_image != context->shell32_size ||
        context->loaded_identity.machine != context->identity.machine ||
        context->loaded_identity.timestamp != context->identity.timestamp ||
        context->loaded_identity.size_of_image != context->identity.size_of_image) {
        fwprintf(
            stderr,
            L"Error: the loaded shell32.dll identity does not exactly match the on-disk image.\n"
            L"Restart Explorer after Windows servicing, then try again.\n");
        close_context(context);
        return -1;
    }

query_mitigation:
    ZeroMemory(&dynamic_code, sizeof(dynamic_code));
    if (GetProcessMitigationPolicy(
            context->explorer,
            ProcessDynamicCodePolicy,
            &dynamic_code,
            sizeof(dynamic_code))) {
        context->dynamic_code_policy_known = 1;
        context->dynamic_code_blocked = dynamic_code.ProhibitDynamicCode != 0;
    }
    return 0;
}

typedef struct SymbolSearch {
    DWORD64 module_base;
    DWORD matches;
    DWORD rva;
    USHORT machine;
} SymbolSearch;

static uint16_t read_u16_le(const unsigned char *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t read_u32_le(const unsigned char *data)
{
    return (uint32_t)data[0] |
        ((uint32_t)data[1] << 8) |
        ((uint32_t)data[2] << 16) |
        ((uint32_t)data[3] << 24);
}

static int ensure_directory(const wchar_t *path)
{
    DWORD attributes;
    if (CreateDirectoryW(path, NULL)) {
        return 0;
    }
    if (GetLastError() != ERROR_ALREADY_EXISTS) {
        return -1;
    }
    attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? 0 : -1;
}

static int pdb_cache_paths(
    const UwdPdbIdentity *pdb,
    int create_directories,
    wchar_t *pdb_name,
    size_t pdb_name_count,
    wchar_t *key,
    size_t key_count,
    wchar_t *directory,
    size_t directory_count,
    wchar_t *file_path,
    size_t file_path_count)
{
    wchar_t data_directory[UWD_PATH_CAP];
    wchar_t symbol_root[UWD_PATH_CAP];
    wchar_t pdb_root[UWD_PATH_CAP];
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    size_t name_index;

    if (pdb == NULL || pdb->pdb_name[0] == '\0' || pdb->age == 0) {
        return -1;
    }
    for (name_index = 0; pdb->pdb_name[name_index] != '\0'; ++name_index) {
        unsigned char c = (unsigned char)pdb->pdb_name[name_index];
        if (!((c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) {
            return -1;
        }
    }
    if (strcmp(pdb->pdb_name, ".") == 0 || strcmp(pdb->pdb_name, "..") == 0 ||
        MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            pdb->pdb_name,
            -1,
            pdb_name,
            (int)pdb_name_count) == 0) {
        return -1;
    }
    data1 = read_u32_le(pdb->guid);
    data2 = read_u16_le(pdb->guid + 4);
    data3 = read_u16_le(pdb->guid + 6);
    if (FAILED(StringCchPrintfW(
            key,
            key_count,
            L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
            (unsigned int)data1,
            (unsigned int)data2,
            (unsigned int)data3,
            (unsigned int)pdb->guid[8],
            (unsigned int)pdb->guid[9],
            (unsigned int)pdb->guid[10],
            (unsigned int)pdb->guid[11],
            (unsigned int)pdb->guid[12],
            (unsigned int)pdb->guid[13],
            (unsigned int)pdb->guid[14],
            (unsigned int)pdb->guid[15],
            (unsigned int)pdb->age))) {
        return -1;
    }
    if (get_data_directory(data_directory, UWD_PATH_CAP, create_directories) != 0 ||
        path_join(symbol_root, UWD_PATH_CAP, data_directory, L"symbols") != 0 ||
        path_join(pdb_root, UWD_PATH_CAP, symbol_root, pdb_name) != 0 ||
        path_join(directory, directory_count, pdb_root, key) != 0 ||
        path_join(file_path, file_path_count, directory, pdb_name) != 0) {
        return -1;
    }
    if (create_directories &&
        (ensure_directory(symbol_root) != 0 ||
         ensure_directory(pdb_root) != 0 ||
         ensure_directory(directory) != 0)) {
        return -1;
    }
    return 0;
}

static int cached_file_exists(const wchar_t *path)
{
    WIN32_FILE_ATTRIBUTE_DATA attributes;
    ULARGE_INTEGER size;

    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &attributes) ||
        (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return 0;
    }
    size.HighPart = attributes.nFileSizeHigh;
    size.LowPart = attributes.nFileSizeLow;
    return size.QuadPart >= 1024;
}

static int download_public_pdb(
    const wchar_t *pdb_name,
    const wchar_t *key,
    const wchar_t *destination)
{
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    wchar_t object_name[1024];
    wchar_t temporary[UWD_PATH_CAP];
    unsigned char buffer[32U * 1024U];
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    DWORD received = 0;
    DWORD written = 0;
    uint64_t total = 0;
    int result = -1;
    DWORD saved_error = ERROR_GEN_FAILURE;

    if (FAILED(StringCchPrintfW(
            object_name,
            sizeof(object_name) / sizeof(object_name[0]),
            L"/download/symbols/%ls/%ls/%ls",
            pdb_name,
            key,
            pdb_name)) ||
        FAILED(StringCchPrintfW(
            temporary,
            UWD_PATH_CAP,
            L"%ls.%lu.download",
            destination,
            GetCurrentProcessId()))) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return -1;
    }

    session = WinHttpOpen(
        L"UniversalWatermarkDisabler/" L"2.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (session == NULL) {
        goto cleanup;
    }
    (void)WinHttpSetTimeouts(session, 15000, 15000, 15000, 60000);
    connection = WinHttpConnect(
        session,
        L"msdl.microsoft.com",
        INTERNET_DEFAULT_HTTPS_PORT,
        0);
    if (connection == NULL) {
        goto cleanup;
    }
    request = WinHttpOpenRequest(
        connection,
        L"GET",
        object_name,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (request == NULL ||
        !WinHttpSendRequest(
            request,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0) ||
        !WinHttpReceiveResponse(request, NULL) ||
        !WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status_code,
            &status_size,
            WINHTTP_NO_HEADER_INDEX)) {
        goto cleanup;
    }
    if (status_code != HTTP_STATUS_OK) {
        SetLastError(status_code == HTTP_STATUS_NOT_FOUND
            ? ERROR_FILE_NOT_FOUND
            : ERROR_WINHTTP_INVALID_SERVER_RESPONSE);
        goto cleanup;
    }

    file = CreateFileW(
        temporary,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    for (;;) {
        if (!WinHttpReadData(request, buffer, (DWORD)sizeof(buffer), &received)) {
            goto cleanup;
        }
        if (received == 0) {
            break;
        }
        total += received;
        if (total > 256ULL * 1024ULL * 1024ULL) {
            SetLastError(ERROR_FILE_TOO_LARGE);
            goto cleanup;
        }
        if (!WriteFile(file, buffer, received, &written, NULL)) {
            goto cleanup;
        }
        if (written != received) {
            SetLastError(ERROR_WRITE_FAULT);
            goto cleanup;
        }
    }
    if (total < 1024 || !FlushFileBuffers(file)) {
        if (total < 1024) {
            SetLastError(ERROR_INVALID_DATA);
        }
        goto cleanup;
    }
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(
            temporary,
            destination,
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (result != 0) {
        saved_error = GetLastError();
    }
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (request != NULL) {
        WinHttpCloseHandle(request);
    }
    if (connection != NULL) {
        WinHttpCloseHandle(connection);
    }
    if (session != NULL) {
        WinHttpCloseHandle(session);
    }
    if (result != 0) {
        (void)DeleteFileW(temporary);
        SetLastError(saved_error);
    }
    return result;
}

static BOOL CALLBACK symbol_callback(
    PSYMBOL_INFOW symbol,
    ULONG symbol_size,
    PVOID user_context)
{
    static const wchar_t undecorated_name[] =
        L"CDesktopWatermark::s_DesktopBuildPaint";
    static const wchar_t decorated_prefix[] =
        L"?s_DesktopBuildPaint@CDesktopWatermark@@";
    SymbolSearch *search = (SymbolSearch *)user_context;
    const ULONG undecorated_length =
        (ULONG)(sizeof(undecorated_name) / sizeof(undecorated_name[0]) - 1);
    const ULONG prefix_length =
        (ULONG)(sizeof(decorated_prefix) / sizeof(decorated_prefix[0]) - 1);
    DWORD64 delta;
    (void)symbol_size;

    if (search->machine == IMAGE_FILE_MACHINE_ARM64) {
        /*
         * An ARM64X PDB can contain classic ARM64 and ARM64EC public symbols.
         * DbgHelp undecorates both to the same name.  Match the classic symbol
         * and reject the documented ARM64EC $$h decoration; ambiguity still
         * fails closed below.
         */
        if (symbol->NameLen < prefix_length ||
            wmemcmp(symbol->Name, decorated_prefix, prefix_length) != 0 ||
            (symbol->NameLen >= prefix_length + 3U &&
             wmemcmp(symbol->Name + prefix_length, L"$$h", 3U) == 0)) {
            return TRUE;
        }
    } else {
        /* Some DbgHelp builds include the trailing NUL in NameLen. */
        if (!((symbol->NameLen == undecorated_length) ||
              (symbol->NameLen == undecorated_length + 1U &&
               symbol->Name[undecorated_length] == L'\0')) ||
            wmemcmp(symbol->Name, undecorated_name, undecorated_length) != 0) {
            return TRUE;
        }
    }
    /* Stripped Microsoft PDBs expose executable functions as PublicCode. */
    if (symbol->Tag != UWD_SYMTAG_FUNCTION &&
        !(symbol->Tag == UWD_SYMTAG_PUBLIC_SYMBOL &&
          (symbol->Flags & SYMFLAG_PUBLIC_CODE) != 0)) {
        return TRUE;
    }
    if (symbol->Address < search->module_base) {
        return TRUE;
    }
    delta = symbol->Address - search->module_base;
    if (delta > UINT32_MAX ||
        (search->machine == IMAGE_FILE_MACHINE_ARM64 && (delta & 3U) != 0)) {
        return TRUE;
    }
    ++search->matches;
    search->rva = (DWORD)delta;
    return TRUE;
}

/*
 * Returns 0 on success, -2 when the cached PDB is missing/corrupt/mismatched,
 * and -1 when DbgHelp or the validated PDB cannot identify one safe function.
 */
static int resolve_cached_symbols(
    const UwdContext *context,
    const UwdPdbIdentity *pdb,
    const wchar_t *search_path,
    DWORD *rva)
{
    HANDLE symbol_process = GetCurrentProcess();
    DWORD64 module_base;
    DWORD previous_options;
    DWORD symbol_options;
    SymbolSearch search;
    IMAGEHLP_MODULEW64 module_info;
    int result = -1;

    previous_options = SymGetOptions();
    symbol_options = previous_options |
        SYMOPT_EXACT_SYMBOLS |
        SYMOPT_FAIL_CRITICAL_ERRORS |
        SYMOPT_SECURE;
    if (context->target_machine == IMAGE_FILE_MACHINE_ARM64) {
        symbol_options &= ~(DWORD)SYMOPT_UNDNAME;
    } else {
        symbol_options |= SYMOPT_UNDNAME;
    }
    (void)SymSetOptions(symbol_options);
    if (!SymInitializeW(symbol_process, search_path, FALSE)) {
        (void)SymSetOptions(previous_options);
        return -1;
    }

    module_base = SymLoadModuleExW(
        symbol_process,
        NULL,
        context->shell32_path,
        NULL,
        0,
        context->shell32_size,
        NULL,
        0);
    if (module_base == 0) {
        result = -2;
        goto cleanup;
    }

    ZeroMemory(&module_info, sizeof(module_info));
    module_info.SizeOfStruct = (DWORD)sizeof(module_info);
    if (!SymGetModuleInfoW64(symbol_process, module_base, &module_info) ||
        module_info.SymType != SymPdb ||
        module_info.PdbUnmatched ||
        module_info.PdbAge != pdb->age ||
        memcmp(&module_info.PdbSig70, pdb->guid, sizeof(pdb->guid)) != 0) {
        result = -2;
        goto cleanup;
    }

    ZeroMemory(&search, sizeof(search));
    search.module_base = module_base;
    search.machine = context->target_machine;
    if (!SymEnumSymbolsW(
            symbol_process,
            module_base,
            L"*DesktopBuildPaint*",
            symbol_callback,
            &search)) {
        result = -2;
        goto cleanup;
    }
    if (search.matches != 1) {
        goto cleanup;
    }
    if (!uwd_pe_rva_is_executable(
            context->image,
            context->image_size,
            search.rva,
            16)) {
        goto cleanup;
    }
    *rva = search.rva;
    result = 0;

cleanup:
    (void)SymCleanup(symbol_process);
    (void)SymSetOptions(previous_options);
    return result;
}

static int resolve_with_symbols(
    const UwdContext *context,
    DWORD *rva,
    const UwdOptions *options)
{
    UwdPdbIdentity pdb;
    wchar_t pdb_name[UWD_PDB_NAME_CAPACITY];
    wchar_t symbol_key[64];
    wchar_t search_path[UWD_PATH_CAP];
    wchar_t pdb_path[UWD_PATH_CAP];
    int cached;
    int resolved;
    int may_update_cache = options != NULL &&
        options->allow_symbol_server && !options->dry_run;

    ZeroMemory(&pdb, sizeof(pdb));
    if (uwd_pe_pdb_identity(
            context->image,
            context->image_size,
            &pdb,
            NULL,
            0) != 0 ||
        pdb_cache_paths(
            &pdb,
            0,
            pdb_name,
            sizeof(pdb_name) / sizeof(pdb_name[0]),
            symbol_key,
            sizeof(symbol_key) / sizeof(symbol_key[0]),
            search_path,
            UWD_PATH_CAP,
            pdb_path,
            UWD_PATH_CAP) != 0) {
        return -1;
    }

    cached = cached_file_exists(pdb_path);
    if (cached) {
        resolved = resolve_cached_symbols(context, &pdb, search_path, rva);
        if (resolved == 0) {
            return 0;
        }
        if (resolved != -2 || !may_update_cache) {
            return -1;
        }
        print_verbose(options, L"Replacing an invalid cached PDB %ls/%ls...", pdb_name, symbol_key);
        if (!DeleteFileW(pdb_path) && GetLastError() != ERROR_FILE_NOT_FOUND) {
            return -1;
        }
    } else if (!may_update_cache) {
        return -1;
    }

    if (pdb_cache_paths(
            &pdb,
            1,
            pdb_name,
            sizeof(pdb_name) / sizeof(pdb_name[0]),
            symbol_key,
            sizeof(symbol_key) / sizeof(symbol_key[0]),
            search_path,
            UWD_PATH_CAP,
            pdb_path,
            UWD_PATH_CAP) != 0) {
        return -1;
    }
    print_verbose(options, L"Downloading exact Microsoft PDB %ls/%ls...", pdb_name, symbol_key);
    if (download_public_pdb(pdb_name, symbol_key, pdb_path) != 0) {
        if (options == NULL || !options->quiet) {
            print_win32_error(L"downloading the Microsoft PDB", GetLastError());
        }
        return -1;
    }
    resolved = resolve_cached_symbols(context, &pdb, search_path, rva);
    if (resolved == -2) {
        (void)DeleteFileW(pdb_path);
    }
    return resolved == 0 ? 0 : -1;
}

int uwd_validate_image_symbols(
    const wchar_t *image_path,
    const UwdOptions *options)
{
    UwdContext context;
    DWORD rva = 0;

    if (image_path == NULL || *image_path == L'\0') {
        fwprintf(stderr, L"Error: an image path is required.\n");
        return 2;
    }
    ZeroMemory(&context, sizeof(context));
    if (FAILED(StringCchCopyW(context.shell32_path, UWD_PATH_CAP, image_path)) ||
        read_entire_file(image_path, &context.image, &context.image_size) != 0 ||
        uwd_pe_identity(
            context.image,
            context.image_size,
            &context.identity,
            NULL,
            0) != 0 ||
        (context.identity.machine != IMAGE_FILE_MACHINE_AMD64 &&
         context.identity.machine != IMAGE_FILE_MACHINE_ARM64)) {
        fwprintf(stderr, L"Error: the image is not a supported x64/ARM64 PE file.\n");
        close_context(&context);
        return 1;
    }
    context.target_machine = context.identity.machine;
    context.shell32_size = context.identity.size_of_image;
    if (resolve_with_symbols(&context, &rva, options) != 0) {
        fwprintf(stderr, L"Error: exact Microsoft PDB symbol validation failed.\n");
        close_context(&context);
        return 1;
    }
    wprintf(
        L"Exact PDB symbol validated: machine=%ls timestamp=0x%08X "
        L"image-size=0x%08X RVA=0x%lX\n",
        machine_name(context.target_machine),
        (unsigned int)context.identity.timestamp,
        (unsigned int)context.identity.size_of_image,
        rva);
    close_context(&context);
    return 0;
}

static int patch_bytes_for_machine(
    USHORT machine,
    unsigned char patch[8],
    size_t *patch_length)
{
    ZeroMemory(patch, 8);
    if (machine == IMAGE_FILE_MACHINE_AMD64) {
        patch[0] = 0xC3; /* ret */
        *patch_length = 1;
        return 0;
    }
    if (machine == IMAGE_FILE_MACHINE_ARM64) {
        /* RET X30, encoded as 0xD65F03C0 in little-endian order. */
        patch[0] = 0xC0;
        patch[1] = 0x03;
        patch[2] = 0x5F;
        patch[3] = 0xD6;
        *patch_length = 4;
        return 0;
    }
    return -1;
}

static int verify_candidate(
    const UwdContext *context,
    DWORD rva,
    int *already_patched)
{
    size_t file_offset;
    size_t compare_length = 16;
    unsigned char live[16];
    unsigned char patch[8];
    size_t patch_length;
    SIZE_T received = 0;

    if (patch_bytes_for_machine(context->target_machine, patch, &patch_length) != 0 ||
        uwd_pe_rva_to_offset(
            context->image,
            context->image_size,
            rva,
            &file_offset) != 0 ||
        file_offset > context->image_size ||
        compare_length > context->image_size - file_offset ||
        rva > context->shell32_size ||
        compare_length > (size_t)context->shell32_size - rva) {
        return -1;
    }

    if (!ReadProcessMemory(
            context->explorer,
            (LPCVOID)(context->shell32_base + rva),
            live,
            compare_length,
            &received) ||
        received != compare_length) {
        return -1;
    }

    if (memcmp(live, context->image + file_offset, compare_length) == 0) {
        *already_patched = 0;
        return 0;
    }
    if (memcmp(live, patch, patch_length) == 0 &&
        memcmp(
            live + patch_length,
            context->image + file_offset + patch_length,
            compare_length - patch_length) == 0) {
        *already_patched = 1;
        return 0;
    }
    return -1;
}

static int resolve_watermark_rva(
    const UwdContext *context,
    DWORD *rva,
    int *already_patched,
    const wchar_t **resolver,
    const UwdOptions *options)
{
    if (resolve_with_symbols(context, rva, options) == 0 &&
        verify_candidate(context, *rva, already_patched) == 0) {
        *resolver = L"Microsoft public symbols";
        return 0;
    }

    fwprintf(
        stderr,
        L"Error: could not safely locate CDesktopWatermark::s_DesktopBuildPaint.\n"
        L"No memory was changed. Microsoft symbols for this exact image are required.\n");
    return -1;
}

static int state_path(
    wchar_t *path,
    size_t path_count,
    DWORD session_id,
    int create_directory)
{
    wchar_t directory[UWD_PATH_CAP];
    wchar_t file_name[64];
    if (get_data_directory(directory, UWD_PATH_CAP, create_directory) != 0) {
        return -1;
    }
    if (FAILED(StringCchPrintfW(
            file_name,
            sizeof(file_name) / sizeof(file_name[0]),
            L"patch-state-%lu.bin",
            session_id))) {
        return -1;
    }
    return path_join(path, path_count, directory, file_name);
}

static int save_state(const UwdPatchState *state)
{
    wchar_t path[UWD_PATH_CAP];
    wchar_t temporary[UWD_PATH_CAP];
    HANDLE file;
    DWORD written = 0;
    UwdPatchState persisted;

    if (state == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }
    persisted = *state;
    ZeroMemory(persisted.state_sha256, sizeof(persisted.state_sha256));
    if (sha256_buffer(
            (const unsigned char *)&persisted,
            offsetof(UwdPatchState, state_sha256),
            persisted.state_sha256) != 0) {
        SetLastError(ERROR_INVALID_DATA);
        return -1;
    }

    if (state_path(path, UWD_PATH_CAP, state->explorer_session_id, 1) != 0 ||
        FAILED(StringCchPrintfW(temporary, UWD_PATH_CAP, L"%ls.tmp", path))) {
        return -1;
    }
    file = CreateFileW(
        temporary,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }
    if (!WriteFile(file, &persisted, (DWORD)sizeof(persisted), &written, NULL) ||
        written != (DWORD)sizeof(persisted) ||
        !FlushFileBuffers(file)) {
        DWORD error = GetLastError();
        CloseHandle(file);
        (void)DeleteFileW(temporary);
        SetLastError(error);
        return -1;
    }
    CloseHandle(file);
    if (!MoveFileExW(
            temporary,
            path,
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD error = GetLastError();
        (void)DeleteFileW(temporary);
        SetLastError(error);
        return -1;
    }
    return 0;
}

static int load_state(UwdPatchState *state)
{
    wchar_t path[UWD_PATH_CAP];
    HANDLE file;
    DWORD received = 0;
    LARGE_INTEGER file_size;
    unsigned char expected_hash[32];
    unsigned char expected_patch[8];
    size_t expected_patch_length = 0;
    size_t index;
    DWORD current_session_id;

    if (!ProcessIdToSessionId(GetCurrentProcessId(), &current_session_id) ||
        state_path(path, UWD_PATH_CAP, current_session_id, 0) != 0) {
        return -1;
    }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? 1 : -1;
    }
    if (!GetFileSizeEx(file, &file_size) ||
        file_size.QuadPart != (LONGLONG)sizeof(*state) ||
        !ReadFile(file, state, (DWORD)sizeof(*state), &received, NULL) ||
        received != (DWORD)sizeof(*state)) {
        CloseHandle(file);
        return -1;
    }
    CloseHandle(file);
    if (memcmp(state->magic, "UWDST3\0", 8) != 0 ||
        state->version != UWD_STATE_VERSION ||
        state->patch_length == 0 ||
        state->patch_length > sizeof(state->patch) ||
        sha256_buffer(
            (const unsigned char *)state,
            offsetof(UwdPatchState, state_sha256),
            expected_hash) != 0 ||
        memcmp(expected_hash, state->state_sha256, sizeof(expected_hash)) != 0 ||
        patch_bytes_for_machine(
            state->machine,
            expected_patch,
            &expected_patch_length) != 0 ||
        state->patch_length != expected_patch_length ||
        memcmp(state->patch, expected_patch, expected_patch_length) != 0 ||
        !is_executable_protection(state->original_protection) ||
        is_writable_executable_protection(state->original_protection) ||
        state->explorer_pid == 0 || state->explorer_creation_time == 0 ||
        state->explorer_session_id != current_session_id ||
        state->shell32_base == 0 ||
        (state->machine == IMAGE_FILE_MACHINE_ARM64 && (state->rva & 3U) != 0)) {
        return -1;
    }
    for (index = expected_patch_length; index < sizeof(state->patch); ++index) {
        if (state->patch[index] != 0 || state->original[index] != 0) {
            return -1;
        }
    }
    return 0;
}

static void delete_state(DWORD session_id)
{
    wchar_t path[UWD_PATH_CAP];
    if (state_path(path, UWD_PATH_CAP, session_id, 0) == 0) {
        (void)DeleteFileW(path);
    }
}

static int is_executable_protection(DWORD protection)
{
    DWORD base = protection & 0xFFU;
    if ((protection & PAGE_GUARD) != 0) {
        return 0;
    }
    return base == PAGE_EXECUTE ||
        base == PAGE_EXECUTE_READ ||
        base == PAGE_EXECUTE_READWRITE ||
        base == PAGE_EXECUTE_WRITECOPY;
}

static int is_writable_executable_protection(DWORD protection)
{
    DWORD base = protection & 0xFFU;
    return base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static int query_remote_protection(
    HANDLE process,
    uintptr_t address,
    size_t byte_count,
    DWORD *protection)
{
    MEMORY_BASIC_INFORMATION region;
    uintptr_t region_base;
    uintptr_t region_end;

    if (protection == NULL || byte_count == 0 ||
        VirtualQueryEx(
            process,
            (LPCVOID)address,
            &region,
            sizeof(region)) != sizeof(region) ||
        region.State != MEM_COMMIT) {
        return -1;
    }
    region_base = (uintptr_t)region.BaseAddress;
    if (region.RegionSize > UINTPTR_MAX - region_base) {
        return -1;
    }
    region_end = region_base + region.RegionSize;
    if (address < region_base || address > region_end ||
        byte_count > region_end - address) {
        return -1;
    }
    *protection = region.Protect;
    return 0;
}

static int restore_remote_protection(
    HANDLE process,
    uintptr_t address,
    size_t byte_count,
    DWORD observed_protection,
    DWORD desired_protection)
{
    DWORD old_protection = 0;
    DWORD ignored = 0;
    DWORD final_observed = 0;
    DWORD requested = desired_protection;

    if (!is_executable_protection(desired_protection)) {
        SetLastError(ERROR_INVALID_DATA);
        return -1;
    }
    requested |= PAGE_TARGETS_NO_UPDATE;
    if (!VirtualProtectEx(
            process,
            (LPVOID)address,
            byte_count,
            requested,
            &old_protection)) {
        return -1;
    }
    if (old_protection != observed_protection) {
        DWORD error = ERROR_RETRY;
        DWORD restore = old_protection;
        if (is_executable_protection(old_protection)) {
            restore |= PAGE_TARGETS_NO_UPDATE;
        }
        if (!VirtualProtectEx(
                process,
                (LPVOID)address,
                byte_count,
                restore,
                &ignored)) {
            error = GetLastError();
        }
        SetLastError(error);
        return -1;
    }
    if (query_remote_protection(
            process,
            address,
            byte_count,
            &final_observed) != 0 ||
        final_observed != desired_protection) {
        SetLastError(ERROR_INVALID_ACCESS);
        return -1;
    }
    return 0;
}

static int write_remote_bytes(
    HANDLE process,
    uintptr_t address,
    const unsigned char *bytes,
    size_t byte_count,
    DWORD final_protection)
{
    DWORD old_protection = 0;
    DWORD ignored = 0;
    SIZE_T written = 0;
    DWORD error = ERROR_SUCCESS;
    DWORD observed_protection = 0;

    if (!is_executable_protection(final_protection)) {
        SetLastError(ERROR_INVALID_DATA);
        return -1;
    }
    if (!VirtualProtectEx(
            process,
            (LPVOID)address,
            byte_count,
            PAGE_EXECUTE_READWRITE | PAGE_TARGETS_NO_UPDATE,
            &old_protection)) {
        return -1;
    }
    if (old_protection != final_protection) {
        DWORD restore_error = ERROR_RETRY;
        DWORD restore_protection = old_protection;
        if (is_executable_protection(old_protection)) {
            restore_protection |= PAGE_TARGETS_NO_UPDATE;
        }
        if (!VirtualProtectEx(
                process,
                (LPVOID)address,
                byte_count,
                restore_protection,
                &ignored)) {
            restore_error = GetLastError();
        }
        SetLastError(restore_error);
        return -1;
    }
    if (!WriteProcessMemory(process, (LPVOID)address, bytes, byte_count, &written)) {
        error = GetLastError();
    } else if (written != byte_count) {
        error = ERROR_WRITE_FAULT;
    } else if (!FlushInstructionCache(process, (LPCVOID)address, byte_count)) {
        error = GetLastError();
    }
    if (!VirtualProtectEx(
            process,
            (LPVOID)address,
            byte_count,
            final_protection | PAGE_TARGETS_NO_UPDATE,
            &ignored) &&
        error == ERROR_SUCCESS) {
        error = GetLastError();
    }
    if (query_remote_protection(
            process,
            address,
            byte_count,
            &observed_protection) != 0 ||
        observed_protection != final_protection) {
        if (error == ERROR_SUCCESS) {
            error = ERROR_INVALID_ACCESS;
        }
    }
    if (error != ERROR_SUCCESS) {
        SetLastError(error);
        return -1;
    }
    return 0;
}

static int verify_remote_bytes_and_protection(
    HANDLE process,
    uintptr_t address,
    const unsigned char *expected,
    size_t byte_count,
    DWORD expected_protection)
{
    unsigned char observed[8];
    SIZE_T received = 0;
    DWORD protection = 0;

    if (expected == NULL || byte_count == 0 || byte_count > sizeof(observed) ||
        !ReadProcessMemory(
            process,
            (LPCVOID)address,
            observed,
            byte_count,
            &received) ||
        received != byte_count ||
        memcmp(observed, expected, byte_count) != 0 ||
        query_remote_protection(
            process,
            address,
            byte_count,
            &protection) != 0 ||
        protection != expected_protection) {
        return -1;
    }
    return 0;
}

enum UwdLivePatchState {
    UWD_LIVE_UNKNOWN = 0,
    UWD_LIVE_ORIGINAL,
    UWD_LIVE_PATCH,
    UWD_LIVE_PARTIAL_PATCH
};

static enum UwdLivePatchState classify_live_patch_bytes(
    const unsigned char *live,
    const UwdPatchState *state)
{
    size_t cut;

    if (memcmp(live, state->original, state->patch_length) == 0) {
        return UWD_LIVE_ORIGINAL;
    }
    if (memcmp(live, state->patch, state->patch_length) == 0) {
        return UWD_LIVE_PATCH;
    }
    for (cut = 1; cut < state->patch_length; ++cut) {
        if (memcmp(live, state->patch, cut) == 0 &&
            memcmp(
                live + cut,
                state->original + cut,
                state->patch_length - cut) == 0) {
            return UWD_LIVE_PARTIAL_PATCH;
        }
    }
    return UWD_LIVE_UNKNOWN;
}

static int rollback_remote_state(
    HANDLE process,
    uintptr_t address,
    const UwdPatchState *state)
{
    unsigned char live[8];
    SIZE_T received = 0;
    DWORD protection = 0;
    enum UwdLivePatchState live_state;

    if (!ReadProcessMemory(
            process,
            (LPCVOID)address,
            live,
            state->patch_length,
            &received) ||
        received != state->patch_length) {
        return -1;
    }
    live_state = classify_live_patch_bytes(live, state);
    if (live_state == UWD_LIVE_UNKNOWN ||
        query_remote_protection(
            process,
            address,
            state->patch_length,
            &protection) != 0) {
        SetLastError(ERROR_INVALID_DATA);
        return -1;
    }
    if (protection != state->original_protection &&
        restore_remote_protection(
            process,
            address,
            state->patch_length,
            protection,
            state->original_protection) != 0) {
        return -1;
    }
    if (live_state != UWD_LIVE_ORIGINAL &&
        write_remote_bytes(
            process,
            address,
            state->original,
            state->patch_length,
            state->original_protection) != 0) {
        return -1;
    }
    if (!FlushInstructionCache(process, (LPCVOID)address, state->patch_length)) {
        return -1;
    }
    return verify_remote_bytes_and_protection(
        process,
        address,
        state->original,
        state->patch_length,
        state->original_protection);
}

static BOOL CALLBACK redraw_desktop_window(HWND window, LPARAM unused)
{
    wchar_t class_name[32];
    HWND view;
    (void)unused;

    if (GetClassNameW(window, class_name, (int)(sizeof(class_name) / sizeof(class_name[0]))) == 0 ||
        (wcscmp(class_name, L"Progman") != 0 && wcscmp(class_name, L"WorkerW") != 0)) {
        return TRUE;
    }
    view = FindWindowExW(window, NULL, L"SHELLDLL_DefView", NULL);
    if (view != NULL) {
        (void)RedrawWindow(
            view,
            NULL,
            NULL,
            RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    }
    return TRUE;
}

static void refresh_desktop(void)
{
    (void)EnumWindows(redraw_desktop_window, 0);
}

static int apply_patch(const UwdOptions *options)
{
    UwdContext context;
    DWORD rva = 0;
    int already_patched = 0;
    const wchar_t *resolver = L"unknown";
    unsigned char patch[8];
    size_t patch_length = 0;
    size_t file_offset = 0;
    UwdPatchState state;
    UwdPatchState saved_state;
    int loaded_state;
    SIZE_T received = 0;
    unsigned char readback[8];
    DWORD original_protection = 0;

    if (open_context(&context, options == NULL || !options->dry_run, 1, options) != 0) {
        return 1;
    }
    if (!context.dynamic_code_policy_known) {
        fwprintf(
            stderr,
            L"Error: Explorer's dynamic-code policy could not be queried; refusing to patch.\n");
        close_context(&context);
        return 1;
    }
    if (context.dynamic_code_blocked) {
        fwprintf(
            stderr,
            L"Error: Explorer's dynamic-code policy blocks safe in-memory patching.\n"
            L"No security mitigation was disabled.\n");
        close_context(&context);
        return 1;
    }
    if (resolve_watermark_rva(
            &context,
            &rva,
            &already_patched,
            &resolver,
            options) != 0) {
        close_context(&context);
        return 1;
    }
    if (patch_bytes_for_machine(context.target_machine, patch, &patch_length) != 0 ||
        uwd_pe_rva_to_offset(context.image, context.image_size, rva, &file_offset) != 0) {
        close_context(&context);
        return 1;
    }

    print_verbose(
        options,
        L"Resolved with %ls: shell32.dll RVA 0x%lX (Explorer PID %lu).",
        resolver,
        rva,
        context.explorer_pid);
    ZeroMemory(&state, sizeof(state));
    memcpy(state.magic, "UWDST3\0", 8);
    state.version = UWD_STATE_VERSION;
    state.explorer_pid = context.explorer_pid;
    state.explorer_session_id = context.explorer_session_id;
    state.explorer_creation_time = context.explorer_creation_time;
    state.shell32_base = context.shell32_base;
    state.machine = context.target_machine;
    state.patch_length = (uint16_t)patch_length;
    state.image_timestamp = context.identity.timestamp;
    state.image_size = context.identity.size_of_image;
    state.rva = rva;
    memcpy(state.image_sha256, context.image_sha256, sizeof(state.image_sha256));
    memcpy(state.original, context.image + file_offset, patch_length);
    memcpy(state.patch, patch, patch_length);

    if (query_remote_protection(
            context.explorer,
            context.shell32_base + rva,
            patch_length,
            &original_protection) != 0) {
        fwprintf(stderr, L"Error: target page is not committed memory.\n");
        close_context(&context);
        return 1;
    }
    state.original_protection = (uint32_t)original_protection;

    if (already_patched) {
        ZeroMemory(&saved_state, sizeof(saved_state));
        loaded_state = load_state(&saved_state);
        if (loaded_state < 0) {
            fwprintf(stderr, L"Error: existing rollback state is corrupt; refusing to overwrite it.\n");
            close_context(&context);
            return 1;
        }
        if (loaded_state == 0) {
            state.original_protection = saved_state.original_protection;
        }
        if (loaded_state == 0 &&
            memcmp(&saved_state, &state, offsetof(UwdPatchState, state_sha256)) == 0) {
            if (original_protection != saved_state.original_protection) {
                if (options != NULL && options->dry_run) {
                    fwprintf(
                        stderr,
                        L"Error: Explorer is patched, but page protection needs repair; dry run made no change.\n");
                    close_context(&context);
                    return 1;
                }
                if (restore_remote_protection(
                        context.explorer,
                        context.shell32_base + rva,
                        patch_length,
                        original_protection,
                        saved_state.original_protection) != 0) {
                    print_win32_error(L"repairing Explorer page protection", GetLastError());
                    close_context(&context);
                    return 1;
                }
            }
            if (verify_remote_bytes_and_protection(
                    context.explorer,
                    context.shell32_base + rva,
                    state.patch,
                    patch_length,
                    state.original_protection) != 0) {
                fwprintf(stderr, L"Error: patched bytes/protection changed during verification.\n");
                close_context(&context);
                return 1;
            }
            print_message(
                options,
                L"The current Explorer process is already patched and has verified rollback state (RVA 0x%lX).",
                rva);
            close_context(&context);
            return 0;
        }
        state.original_protection = (uint32_t)original_protection;
        if (options != NULL && options->dry_run) {
            fwprintf(
                stderr,
                L"Error: Explorer is patched, but matching rollback state is missing.\n"
                L"Run --apply without --dry-run to reconstruct verified rollback state.\n");
            close_context(&context);
            return 1;
        }
        if (!is_executable_protection(original_protection) ||
            is_writable_executable_protection(original_protection)) {
            fwprintf(
                stderr,
                L"Error: rollback state is missing and current page protection is unsafe to adopt.\n");
            close_context(&context);
            return 1;
        }
        if (save_state(&state) != 0) {
            print_win32_error(L"reconstructing the rollback state", GetLastError());
            close_context(&context);
            return 1;
        }
        print_message(
            options,
            L"Explorer was already patched; verified rollback state was reconstructed (RVA 0x%lX).",
            rva);
        close_context(&context);
        return 0;
    }

    if (!is_executable_protection(original_protection) ||
        is_writable_executable_protection(original_protection)) {
        fwprintf(stderr, L"Error: target page is not read-only executable memory.\n");
        close_context(&context);
        return 1;
    }

    if (options != NULL && options->dry_run) {
        print_message(
            options,
            L"Dry run passed: the target was verified and no memory, registry, or cache was changed.");
        close_context(&context);
        return 0;
    }

    if (!ReadProcessMemory(
            context.explorer,
            (LPCVOID)(context.shell32_base + rva),
            readback,
            patch_length,
            &received) ||
        received != patch_length ||
        memcmp(readback, state.original, patch_length) != 0) {
        fwprintf(stderr, L"Error: live function bytes changed during verification.\n");
        close_context(&context);
        return 1;
    }
    if (save_state(&state) != 0) {
        print_win32_error(L"saving the rollback state", GetLastError());
        close_context(&context);
        return 1;
    }
    if (write_remote_bytes(
            context.explorer,
            context.shell32_base + rva,
            patch,
            patch_length,
            state.original_protection) != 0) {
        DWORD write_error = GetLastError();
        /* The state is kept unless a verified immediate rollback succeeds. */
        if (rollback_remote_state(
                context.explorer,
                context.shell32_base + rva,
                &state) == 0) {
            delete_state(state.explorer_session_id);
        }
        print_win32_error(L"writing Explorer memory", write_error);
        close_context(&context);
        return 1;
    }
    if (verify_remote_bytes_and_protection(
            context.explorer,
            context.shell32_base + rva,
            patch,
            patch_length,
            state.original_protection) != 0) {
        fwprintf(stderr, L"Error: Explorer readback/protection did not match the patch.\n");
        if (rollback_remote_state(
                context.explorer,
                context.shell32_base + rva,
                &state) == 0) {
            delete_state(state.explorer_session_id);
        }
        close_context(&context);
        return 1;
    }

    if (options == NULL || options->refresh_desktop) {
        refresh_desktop();
    }
    print_message(
        options,
        L"Applied to Explorer PID %lu. System files were not modified.",
        context.explorer_pid);
    close_context(&context);
    return 0;
}

static int restore_patch(const UwdOptions *options)
{
    UwdPatchState state;
    UwdContext context;
    int loaded = load_state(&state);
    unsigned char live[8];
    SIZE_T received = 0;
    DWORD current_protection = 0;
    enum UwdLivePatchState live_state;

    if (loaded == 1) {
        print_message(options, L"No rollback state exists; there is nothing to restore.");
        return 0;
    }
    if (loaded != 0) {
        fwprintf(stderr, L"Error: the rollback state is corrupt or unreadable.\n");
        return 1;
    }
    if (open_context(&context, options == NULL || !options->dry_run, 0, options) != 0) {
        return 1;
    }

    if (state.explorer_pid != context.explorer_pid ||
        state.explorer_session_id != context.explorer_session_id ||
        state.explorer_creation_time != context.explorer_creation_time ||
        state.shell32_base != context.shell32_base ||
        state.machine != context.target_machine) {
        if (options == NULL || !options->dry_run) {
            delete_state(state.explorer_session_id);
        }
        print_message(
            options,
            L"Explorer has restarted or shell32.dll changed; the in-memory patch is already gone.");
        close_context(&context);
        return 0;
    }
    if (state.image_timestamp != context.loaded_identity.timestamp ||
        state.image_size != context.loaded_identity.size_of_image) {
        fwprintf(
            stderr,
            L"Error: rollback state does not match the loaded shell32.dll image.\n");
        close_context(&context);
        return 1;
    }
    if (!is_executable_protection(state.original_protection) ||
        state.rva > context.shell32_size ||
        state.patch_length > (size_t)context.shell32_size - state.rva ||
        !ReadProcessMemory(
            context.explorer,
            (LPCVOID)(context.shell32_base + state.rva),
            live,
            state.patch_length,
            &received) ||
        received != state.patch_length) {
        fwprintf(stderr, L"Error: the saved rollback address is no longer valid.\n");
        close_context(&context);
        return 1;
    }
    if (query_remote_protection(
            context.explorer,
            context.shell32_base + state.rva,
            state.patch_length,
            &current_protection) != 0) {
        fwprintf(stderr, L"Error: could not query the saved rollback page.\n");
        close_context(&context);
        return 1;
    }
    live_state = classify_live_patch_bytes(live, &state);
    if (live_state == UWD_LIVE_UNKNOWN) {
        fwprintf(
            stderr,
            L"Error: another program changed the target bytes; refusing an unsafe restore.\n");
        close_context(&context);
        return 1;
    }
    if (current_protection != state.original_protection) {
        if (options != NULL && options->dry_run) {
            fwprintf(
                stderr,
                L"Error: rollback page protection needs repair; dry run made no change.\n");
            close_context(&context);
            return 1;
        }
        if (restore_remote_protection(
                context.explorer,
                context.shell32_base + state.rva,
                state.patch_length,
                current_protection,
                state.original_protection) != 0) {
            print_win32_error(L"restoring Explorer page protection", GetLastError());
            close_context(&context);
            return 1;
        }
    }

    if (live_state == UWD_LIVE_ORIGINAL) {
        if (options != NULL && options->dry_run) {
            print_message(
                options,
                L"Dry run: original bytes/protection match; rollback state was retained.");
            close_context(&context);
            return 0;
        }
        if (!FlushInstructionCache(
                context.explorer,
                (LPCVOID)(context.shell32_base + state.rva),
                state.patch_length) ||
            verify_remote_bytes_and_protection(
                context.explorer,
                context.shell32_base + state.rva,
                state.original,
                state.patch_length,
                state.original_protection) != 0) {
            fwprintf(
                stderr,
                L"Error: original bytes/protection/cache could not be verified; rollback state was retained.\n");
            close_context(&context);
            return 1;
        }
        delete_state(state.explorer_session_id);
        print_message(options, L"The original Explorer bytes are already restored.");
        close_context(&context);
        return 0;
    }
    if (options != NULL && options->dry_run) {
        print_message(options, L"Dry run passed: rollback state and live bytes are recoverable.");
        close_context(&context);
        return 0;
    }
    if (write_remote_bytes(
            context.explorer,
            context.shell32_base + state.rva,
            state.original,
            state.patch_length,
            state.original_protection) != 0) {
        print_win32_error(L"restoring Explorer memory", GetLastError());
        close_context(&context);
        return 1;
    }
    if (verify_remote_bytes_and_protection(
            context.explorer,
            context.shell32_base + state.rva,
            state.original,
            state.patch_length,
            state.original_protection) != 0) {
        fwprintf(
            stderr,
            L"Error: restore readback/protection did not match; rollback state was retained.\n");
        close_context(&context);
        return 1;
    }
    delete_state(state.explorer_session_id);
    if (options == NULL || options->refresh_desktop) {
        refresh_desktop();
    }
    print_message(options, L"Restored the current Explorer process.");
    close_context(&context);
    return 0;
}

static int set_startup(int enabled, const UwdOptions *options)
{
    wchar_t executable[UWD_PATH_CAP];
    wchar_t command[UWD_PATH_CAP];
    HKEY key = NULL;
    LONG status;
    DWORD length;

    if (enabled) {
        length = GetModuleFileNameW(NULL, executable, UWD_PATH_CAP);
        if (length == 0 || length >= UWD_PATH_CAP) {
            print_win32_error(L"GetModuleFileNameW", GetLastError());
            return 1;
        }
        if (FAILED(StringCchPrintfW(
                command,
                UWD_PATH_CAP,
                L"\"%ls\" --apply --quiet --wait 60%ls%ls",
                executable,
                options != NULL && !options->allow_symbol_server ? L" --offline" : L"",
                options != NULL && !options->refresh_desktop ? L" --no-refresh" : L""))) {
            fwprintf(stderr, L"Error: executable path is too long for the startup entry.\n");
            return 1;
        }
    }

    if (options != NULL && options->dry_run) {
        print_message(
            options,
            enabled ? L"Dry run: would enable per-user startup." : L"Dry run: would disable per-user startup.");
        return 0;
    }

    if (enabled) {
        status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            UWD_RUN_KEY,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            NULL,
            &key,
            NULL);
    } else {
        status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            UWD_RUN_KEY,
            0,
            KEY_SET_VALUE,
            &key);
        if (status == ERROR_FILE_NOT_FOUND) {
            print_message(options, L"Per-user startup is already disabled.");
            return 0;
        }
    }
    if (status != ERROR_SUCCESS) {
        print_win32_error(L"opening the current-user Run key", (DWORD)status);
        return 1;
    }

    if (enabled) {
        status = RegSetValueExW(
            key,
            UWD_RUN_VALUE,
            0,
            REG_SZ,
            (const BYTE *)command,
            (DWORD)((wcslen(command) + 1) * sizeof(wchar_t)));
    } else {
        status = RegDeleteValueW(key, UWD_RUN_VALUE);
        if (status == ERROR_FILE_NOT_FOUND) {
            status = ERROR_SUCCESS;
        }
    }
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) {
        print_win32_error(enabled ? L"enabling startup" : L"disabling startup", (DWORD)status);
        return 1;
    }

    print_message(
        options,
        enabled
            ? L"Enabled per-user startup. Keep this executable at its current path."
            : L"Disabled per-user startup.");
    return 0;
}

static int show_diagnostics(const UwdOptions *options)
{
    UwdContext context;
    DWORD rva = 0;
    int already_patched = 0;
    const wchar_t *resolver = L"unresolved";
    int resolved;
    uint32_t heuristic_rva = 0;
    char heuristic_error[256];
    int heuristic_result = -1;

    if (open_context(&context, 0, 1, options) != 0) {
        return 1;
    }
    resolved = resolve_watermark_rva(
        &context,
        &rva,
        &already_patched,
        &resolver,
        options);
    heuristic_error[0] = '\0';
    if (options != NULL && options->show_offline_candidate &&
        context.target_machine == IMAGE_FILE_MACHINE_AMD64) {
        heuristic_result = uwd_pe_find_watermark_rva(
            context.image,
            context.image_size,
            &heuristic_rva,
            heuristic_error,
            sizeof(heuristic_error));
    }

    wprintf(L"Universal Watermark Disabler %hs diagnostics\n", UWD_VERSION);
    wprintf(
        L"  OS                 : Windows %ls, build %lu\n",
        context.os_build >= 22000 ? L"11" : L"10",
        context.os_build);
    wprintf(
        L"  Process            : explorer.exe (PID %lu, session %lu)\n",
        context.explorer_pid,
        context.explorer_session_id);
    wprintf(L"  Architecture       : %ls\n", machine_name(context.target_machine));
    wprintf(L"  shell32.dll        : %ls\n", context.shell32_path);
    wprintf(
        L"  Image timestamp    : 0x%08X\n",
        (unsigned int)context.identity.timestamp);
    wprintf(
        L"  Image size         : 0x%08X\n",
        (unsigned int)context.identity.size_of_image);
    wprintf(L"  Image SHA-256      : ");
    {
        size_t hash_index;
        for (hash_index = 0; hash_index < sizeof(context.image_sha256); ++hash_index) {
            wprintf(L"%02X", (unsigned int)context.image_sha256[hash_index]);
        }
        wprintf(L"\n");
    }
    wprintf(L"  Dynamic-code policy: %ls\n",
        !context.dynamic_code_policy_known
            ? L"unknown (Apply fails closed)"
            : (context.dynamic_code_blocked ? L"blocked" : L"allows patching"));
    if (resolved == 0) {
        wprintf(L"  Resolver           : %ls\n", resolver);
        wprintf(L"  Target RVA         : 0x%lX\n", rva);
        wprintf(L"  Current state      : %ls\n", already_patched ? L"patched" : L"original");
    } else {
        wprintf(L"  Resolver           : failed (no memory was changed)\n");
    }
    if (options != NULL && options->show_offline_candidate) {
        if (heuristic_result == 0) {
            wprintf(
                L"  Heuristic candidate: 0x%X (diagnostics only; never applied)%ls\n",
                (unsigned int)heuristic_rva,
                resolved == 0 && heuristic_rva != rva ? L" [DIFFERS FROM PDB]" : L"");
        } else {
            wprintf(L"  Heuristic candidate: unavailable (%hs)\n", heuristic_error);
        }
    }
    wprintf(L"  System files       : never modified\n");

    close_context(&context);
    return resolved == 0 ? 0 : 1;
}

static HANDLE acquire_patch_transaction(void)
{
    HANDLE mutex = CreateMutexW(
        NULL,
        FALSE,
        L"Local\\UniversalWatermarkDisabler-PatchTransaction-v2");
    DWORD wait_result;

    if (mutex == NULL) {
        return NULL;
    }
    wait_result = WaitForSingleObject(mutex, 120000);
    if (wait_result == WAIT_OBJECT_0 || wait_result == WAIT_ABANDONED) {
        return mutex;
    }
    if (wait_result == WAIT_TIMEOUT) {
        SetLastError(ERROR_TIMEOUT);
    }
    CloseHandle(mutex);
    return NULL;
}

int uwd_execute(UwdAction action, const UwdOptions *options)
{
    UwdOptions defaults;
    HANDLE transaction = NULL;
    int result;

    if (options == NULL) {
        ZeroMemory(&defaults, sizeof(defaults));
        defaults.allow_symbol_server = 1;
        defaults.show_offline_candidate = 0;
        defaults.refresh_desktop = 1;
        options = &defaults;
    }

    if (action == UWD_ACTION_APPLY || action == UWD_ACTION_RESTORE) {
        transaction = acquire_patch_transaction();
        if (transaction == NULL) {
            print_win32_error(L"waiting for another Apply/Restore operation", GetLastError());
            return 1;
        }
    }

    switch (action) {
    case UWD_ACTION_APPLY:
        result = apply_patch(options);
        break;
    case UWD_ACTION_RESTORE:
        result = restore_patch(options);
        break;
    case UWD_ACTION_ENABLE_STARTUP:
        result = set_startup(1, options);
        break;
    case UWD_ACTION_DISABLE_STARTUP:
        result = set_startup(0, options);
        break;
    case UWD_ACTION_DIAGNOSTICS:
        result = show_diagnostics(options);
        break;
    default:
        fwprintf(stderr, L"Error: unknown action.\n");
        result = 2;
        break;
    }
    if (transaction != NULL) {
        (void)ReleaseMutex(transaction);
        CloseHandle(transaction);
    }
    return result;
}
