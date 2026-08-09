# Universal TUI

A dependency-free, single-engine **`make menuconfig`-style terminal UI** in C99.
Describe a tree of typed configuration items as static data, hand it to
`ut_run()`, and get the full lxdialog experience — 3D dialogs, hotkeys,
`y`/`n`/`m`, help, search with jump, `.config` save/load, mouse, live resize,
ASCII fallback — with **no ncurses and no dependencies** beyond libc and the OS
terminal API.

**Portable across POSIX (Linux / macOS / BSD) and pure Windows (Win32 Console
API)** from one source. Rendering is direct VT100/xterm escapes; on Windows the
engine enables `ENABLE_VIRTUAL_TERMINAL_PROCESSING` for output and translates
`ReadConsoleInputW` events into VT byte streams for input (works on Windows 7+
and Wine, not only Windows 10 VT-input).

```
utui.h            public API (item tree, UtApp, ut_run/ut_main/ut_load/ut_save)
utui.c            the engine (compile once, reuse everywhere)
examples/demo.c   a complete example ("acme-server" configurator)
tests/            pty-driven behavioural tests
```

## Quick start

```c
#include "utui.h"

static UtItem net[] = {
    UT_STR ("Listen address", "ADDR", "0.0.0.0", NULL),
    UT_INT ("Listen port",    "PORT", "8080",    "The TCP port to bind."),
    UT_BOOL(2, "Enable HTTP/2", "HTTP2", NULL),
};
static UtItem main_items[] = {
    UT_MENU("Networking", net),
    UT_TRI (1, "Metrics exporter", "METRICS", NULL),
    UT_FORCED("Core scheduler", "CORE", "Always built in."),
};
static UtItem root = UT_ROOT("My App Configuration", main_items);

int main(int argc, char **argv)
{
    UtApp app = {
        ".config - My App",          /* backtitle          */
        "My App Configuration",      /* title              */
        "myapp.config",              /* config file        */
        "MYAPP",                     /* CONFIG_MYAPP_<SYM> ("" for CONFIG_<SYM>) */
        NULL,                        /* instructions (NULL = default)           */
        "myapp-config",              /* --version name     */
        "\nSaved.\n",                /* epilogue on save   */
        -1                           /* ascii: -1 auto, 0 unicode, 1 ascii      */
    };
    return ut_main(&root, &app, argc, argv);
}
```

```bash
cc -std=c99 -O2 -I. -o myapp-config myapp.c utui.c   # POSIX
x86_64-w64-mingw32-gcc -std=c99 -O2 -I. -o myapp-config.exe myapp.c utui.c
# MSVC:  cl /std:c11 /I. myapp.c utui.c
```

## Item kinds

| Constructor | Renders | Meaning |
|---|---|---|
| `UT_BOOL(v,name,sym,help)` | `[ ]` / `[*]` | boolean (`v` = 0 or 2) |
| `UT_TRI(v,name,sym,help)` | `< >` / `<M>` / `<*>` | tristate (0/1/2) |
| `UT_FORCED(name,sym,help)` | `-*-` | always-on, not user-changeable |
| `UT_STR(name,sym,"val",help)` | `(val)` | string value |
| `UT_INT(name,sym,"123",help)` | `(123)` | integer value (digits only) |
| `UT_MENU(name,kids)` | `name  --->` | submenu |
| `UT_SUBMENU(v,name,sym,help,kids)` | `[*] name  --->` | bool that is also a submenu |
| `UT_CHOICE(idx,name,kids)` / `UT_CHOICE_H(idx,name,help,kids)` | `name (current)  --->` | radio group |
| `UT_RADIO(name,sym)` | `(X)` / `( )` | one option inside a choice |
| `UT_COMMENT(name)` | `*** name ***` | non-selectable divider |
| `UT_ROOT(title,kids)` | — | the top-level menu passed to `ut_run` |

Each `UtItem` array must be a distinct C array (do not alias one array into two
menus). The engine fills in `parent`/`idx`; you only set the fields the macros
take.

## Keys

Arrows / PgUp/PgDn / Home/End move; `Tab`/`←`/`→` move between the
`<Select> <Exit> <Help> <Save> <Load>` buttons; `Enter` activates; `Space`
toggles / cycles / selects; `y`/`n`/`m` set values; a letter jumps to the next
item with that hotkey; `?` shows help; `/` searches (jump to a result with its
`(1)`–`(9)` number); `Esc` backs out (and prompts to save at the top). Mouse
click selects and re-click activates; the wheel scrolls.

## API

```c
int ut_run (UtItem *root, const UtApp *app);                 /* 1=saved 0=not -1=no tty */
int ut_main(UtItem *root, UtApp  *app, int argc, char **argv);/* CLI wrapper -> exit code */
int ut_load(UtItem *root, const UtApp *app, const char *path);/* headless load, 0 ok      */
int ut_save(UtItem *root, const UtApp *app, const char *path);/* headless save, 0 ok      */
```

`.config` format: `CONFIG_<prefix>_<SYM>=y|m|"str"|int` and
`# CONFIG_<prefix>_<SYM> is not set`, matching Linux Kconfig. With an empty
`sym_prefix` it degrades to plain `CONFIG_<SYM>`.

## Build & test

```bash
make            # libutui.a + demo
make windows    # demo.exe (MinGW cross)
make asan       # demo-asan (ASan/UBSan)
make test       # python3 tests/test_demo.py ./demo
```

The engine builds warning-clean under `gcc`/`clang -std=c99 -Wall -Wextra
-pedantic -Werror` and MinGW, and the demo passes the pty test suite under
ASan/UBSan.

## Users

- [photo-to-dom](https://github.com/ayanami770/photo-to-dom) embeds this as a
  submodule to provide `photo2dom-menuconfig`.

## License

Apache-2.0. See `LICENSE`.
