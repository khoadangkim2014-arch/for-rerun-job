#ifndef UWD_H
#define UWD_H

#include <stddef.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UWD_VERSION "2.0.0-dev"

typedef enum UwdAction {
    UWD_ACTION_APPLY = 0,
    UWD_ACTION_RESTORE,
    UWD_ACTION_ENABLE_STARTUP,
    UWD_ACTION_DISABLE_STARTUP,
    UWD_ACTION_DIAGNOSTICS
} UwdAction;

typedef struct UwdOptions {
    int allow_symbol_server;
    int show_offline_candidate;
    int refresh_desktop;
    int dry_run;
    int quiet;
    unsigned int wait_seconds;
} UwdOptions;

/*
 * Execute one backend action. The backend only changes the current Explorer
 * process and the current user's optional Run entry; it never edits a Windows
 * system file. A zero return value means success.
 */
int uwd_execute(UwdAction action, const UwdOptions *options);

/* Resolve the exact watermark symbol in a disk image without opening Explorer. */
int uwd_validate_image_symbols(
    const wchar_t *image_path,
    const UwdOptions *options);

/* Return/create %LOCALAPPDATA%\UniversalWatermarkDisabler. */
int uwd_get_data_directory(wchar_t *buffer, size_t buffer_count);

#ifdef __cplusplus
}
#endif

#endif /* UWD_H */
