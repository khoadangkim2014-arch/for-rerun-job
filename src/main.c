#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <strsafe.h>

#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "utui.h"
#include "uwd.h"

#define CONFIG_UTF8_CAP (32768U * 4U)

enum {
    MAIN_ACTION = 0
};

enum {
    SETTING_SYMBOL_SERVER = 0,
    SETTING_OFFLINE_SCAN = 1,
    SETTING_REFRESH = 2,
    SETTING_DRY_RUN = 3
};

static const char HELP_ACTION[] =
    "Choose exactly one operation. Saving and leaving the TUI executes the "
    "selected operation. Exit without saving to cancel.";

static const char HELP_SYMBOLS[] =
    "Use Microsoft's public symbol server when the exact shell32 symbols are "
    "not already cached. This is the safest resolver and is enabled by default.";

static const char HELP_OFFLINE_SCAN[] =
    "Show the experimental x64 PE/GDI/.pdata candidate in Diagnostics. The "
    "candidate is never used for Apply: validation on a current Windows build "
    "proved that this heuristic can select the wrong private shell function.";

static const char HELP_DRY_RUN[] =
    "Resolve and verify the target without changing Explorer memory or the "
    "current-user startup entry. Universal-TUI still saves this configuration.";

static UtItem action_items[] = {
    UT_RADIO("Apply to the current Explorer session", "ACTION_APPLY"),
    UT_RADIO("Restore the current Explorer session", "ACTION_RESTORE"),
    UT_RADIO("Enable per-user startup", "ACTION_ENABLE_STARTUP"),
    UT_RADIO("Disable per-user startup", "ACTION_DISABLE_STARTUP"),
    UT_RADIO("Run diagnostics only", "ACTION_DIAGNOSTICS"),
};

static UtItem settings_items[] = {
    UT_BOOL(2, "Allow Microsoft public symbols", "SYMBOL_SERVER", HELP_SYMBOLS),
    UT_BOOL(0, "Show experimental offline candidate (Diagnostics only)", "OFFLINE_SCAN", HELP_OFFLINE_SCAN),
    UT_BOOL(2, "Refresh the desktop after a memory change", "REFRESH", NULL),
    UT_BOOL(0, "Dry run (no Explorer/registry changes)", "DRY_RUN", HELP_DRY_RUN),
};

static UtItem main_items[] = {
    UT_CHOICE_H(4, "Action", HELP_ACTION, action_items),
    UT_MENU("Safety and resolver settings", settings_items),
    UT_COMMENT("Scope"),
    UT_FORCED(
        "Current-user, in-memory change only",
        "NO_SYSTEM_FILE_CHANGES",
        "The modern backend does not replace COM registrations, weaken ACLs, "
        "or write files under the Windows directory."),
    UT_FORCED(
        "Activation watermark is intentionally out of scope",
        "NO_ACTIVATION_BYPASS",
        "This project is for Insider/evaluation build text. It does not bypass "
        "Windows activation or licensing."),
};

static UtItem root = UT_ROOT("Universal Watermark Disabler", main_items);

static void print_help(const wchar_t *program)
{
    wprintf(
        L"Universal Watermark Disabler %hs\n\n"
        L"Usage:\n"
        L"  %ls                         Open the Universal-TUI interface\n"
        L"  %ls --apply                 Apply to the current Explorer session\n"
        L"  %ls --restore               Restore the saved original bytes\n"
        L"  %ls --enable-startup        Apply automatically at user logon\n"
        L"  %ls --disable-startup       Remove the per-user startup entry\n"
        L"  %ls --diagnostics           Report without changing Explorer/registry\n\n"
        L"Options:\n"
        L"  --offline                   Do not contact the Microsoft symbol server\n"
        L"  --experimental-offline-scan Show the heuristic candidate (Diagnostics only)\n"
        L"  --dry-run                   Verify only; use cached symbols; no writes\n"
        L"  --no-refresh                Do not request a desktop redraw\n"
        L"  --wait SECONDS              Wait up to 600 seconds for Explorer\n"
        L"  --quiet                     Suppress success/status output\n"
        L"  --ascii | --unicode         Select the TUI drawing mode\n"
        L"  --version                   Print the version\n"
        L"  --help                      Show this help\n\n"
        L"The tool never modifies Windows system files. It does not remove the\n"
        L"Activate Windows watermark or change licensing state.\n",
        UWD_VERSION,
        program,
        program,
        program,
        program,
        program,
        program);
}

static int parse_wait_seconds(const wchar_t *value, unsigned int *seconds)
{
    wchar_t *end = NULL;
    unsigned long parsed;

    if (value == NULL || *value == L'\0') {
        return -1;
    }
    errno = 0;
    parsed = wcstoul(value, &end, 10);
    if (errno == ERANGE || end == value || *end != L'\0' || parsed > 600UL) {
        return -1;
    }
    *seconds = (unsigned int)parsed;
    return 0;
}

static int build_config_path(char *utf8_path, size_t utf8_path_count)
{
    wchar_t directory[32768];
    wchar_t wide_path[32768];
    int converted;

    if (uwd_get_data_directory(directory, sizeof(directory) / sizeof(directory[0])) != 0 ||
        FAILED(StringCchPrintfW(
            wide_path,
            sizeof(wide_path) / sizeof(wide_path[0]),
            L"%ls\\uwd.config",
            directory))) {
        return -1;
    }

    converted = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        wide_path,
        -1,
        utf8_path,
        (int)utf8_path_count,
        NULL,
        NULL);
    return converted > 0 ? 0 : -1;
}

static UwdOptions options_from_tui(void)
{
    UwdOptions options;
    ZeroMemory(&options, sizeof(options));
    options.allow_symbol_server = settings_items[SETTING_SYMBOL_SERVER].value != 0;
    options.show_offline_candidate = settings_items[SETTING_OFFLINE_SCAN].value != 0;
    options.refresh_desktop = settings_items[SETTING_REFRESH].value != 0;
    options.dry_run = settings_items[SETTING_DRY_RUN].value != 0;
    return options;
}

static int run_tui(int ascii_mode)
{
    static char config_path[CONFIG_UTF8_CAP];
    UwdOptions options;
    UtApp app;
    int result;

    if (build_config_path(config_path, sizeof(config_path)) != 0) {
        memcpy(config_path, "uwd.config", sizeof("uwd.config"));
    }

    ZeroMemory(&app, sizeof(app));
    app.backtitle = "Universal Watermark Disabler 2 - Windows 10/11";
    app.title = "Universal Watermark Disabler";
    app.config_file = config_path;
    app.sym_prefix = "UWD";
    app.instructions =
        "Select an action and settings. Save executes the selected action; "
        "Exit cancels. Unknown targets fail closed without changing memory.";
    app.app_name = "uwd";
    app.saved_epilogue = NULL;
    app.ascii = ascii_mode;
    app.exit_after_save = 1;

    result = ut_run(&root, &app);
    if (result < 0) {
        fwprintf(
            stderr,
            L"Error: Universal-TUI requires an interactive console. "
            L"Use --help for non-interactive commands.\n");
        return 2;
    }
    if (result == 0) {
        return 0;
    }

    options = options_from_tui();
    return uwd_execute((UwdAction)main_items[MAIN_ACTION].value, &options);
}

int wmain(int argc, wchar_t **argv)
{
    UwdOptions options;
    UwdAction action = UWD_ACTION_APPLY;
    int action_set = 0;
    int backend_option_set = 0;
    int ascii_mode = -1;
    int index;

    (void)setlocale(LC_ALL, "");
    (void)SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        fwprintf(stderr, L"Error: could not secure the DLL search path (%lu).\n", GetLastError());
        return 1;
    }

    ZeroMemory(&options, sizeof(options));
    options.allow_symbol_server = 1;
    options.show_offline_candidate = 0;
    options.refresh_desktop = 1;

    for (index = 1; index < argc; ++index) {
        if (wcscmp(argv[index], L"--apply") == 0) {
            action = UWD_ACTION_APPLY;
            ++action_set;
        } else if (wcscmp(argv[index], L"--restore") == 0) {
            action = UWD_ACTION_RESTORE;
            ++action_set;
        } else if (wcscmp(argv[index], L"--enable-startup") == 0) {
            action = UWD_ACTION_ENABLE_STARTUP;
            ++action_set;
        } else if (wcscmp(argv[index], L"--disable-startup") == 0) {
            action = UWD_ACTION_DISABLE_STARTUP;
            ++action_set;
        } else if (wcscmp(argv[index], L"--diagnostics") == 0) {
            action = UWD_ACTION_DIAGNOSTICS;
            ++action_set;
        } else if (wcscmp(argv[index], L"--offline") == 0) {
            options.allow_symbol_server = 0;
            backend_option_set = 1;
        } else if (wcscmp(argv[index], L"--experimental-offline-scan") == 0) {
            options.show_offline_candidate = 1;
            backend_option_set = 1;
        } else if (wcscmp(argv[index], L"--dry-run") == 0) {
            options.dry_run = 1;
            backend_option_set = 1;
        } else if (wcscmp(argv[index], L"--no-refresh") == 0) {
            options.refresh_desktop = 0;
            backend_option_set = 1;
        } else if (wcscmp(argv[index], L"--quiet") == 0) {
            options.quiet = 1;
            backend_option_set = 1;
        } else if (wcscmp(argv[index], L"--ascii") == 0) {
            ascii_mode = 1;
        } else if (wcscmp(argv[index], L"--unicode") == 0) {
            ascii_mode = 0;
        } else if (wcscmp(argv[index], L"--wait") == 0) {
            if (++index >= argc || parse_wait_seconds(argv[index], &options.wait_seconds) != 0) {
                fwprintf(stderr, L"Error: --wait requires a value from 0 to 600.\n");
                return 2;
            }
            backend_option_set = 1;
        } else if (wcscmp(argv[index], L"--version") == 0) {
            printf("uwd %s (Universal-TUI %s)\n", UWD_VERSION, UTUI_VERSION);
            return 0;
        } else if (wcscmp(argv[index], L"--help") == 0 ||
                   wcscmp(argv[index], L"-h") == 0) {
            print_help(argv[0]);
            return 0;
        } else {
            fwprintf(stderr, L"Error: unknown option: %ls\n", argv[index]);
            print_help(argv[0]);
            return 2;
        }
    }

    if (action_set > 1) {
        fwprintf(stderr, L"Error: choose only one action.\n");
        return 2;
    }
    if (action_set == 1 && options.show_offline_candidate &&
        action != UWD_ACTION_DIAGNOSTICS) {
        fwprintf(
            stderr,
            L"Error: --experimental-offline-scan is diagnostics-only and can never be used for Apply.\n");
        return 2;
    }
    if (action_set == 1) {
        return uwd_execute(action, &options);
    }
    if (backend_option_set) {
        fwprintf(
            stderr,
            L"Error: backend options require one explicit action such as --diagnostics or --apply.\n");
        return 2;
    }
    return run_tui(ascii_mode);
}
