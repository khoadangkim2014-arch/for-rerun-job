#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <stdio.h>

#include "../src/uwd.h"

int wmain(int argc, wchar_t **argv)
{
    UwdOptions options;

    if (argc != 2) {
        fwprintf(stderr, L"Usage: %ls shell32.dll\n", argv[0]);
        return 2;
    }
    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        fwprintf(stderr, L"Error: could not secure the DLL search path (%lu).\n", GetLastError());
        return 1;
    }
    ZeroMemory(&options, sizeof(options));
    options.allow_symbol_server = 1;
    return uwd_validate_image_symbols(argv[1], &options);
}
