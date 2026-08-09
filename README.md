# Universal Watermark Disabler 2

[日本語](README.ja.md)

This fork modernizes Painter701's 2015 Universal Watermark Disabler for current
Windows 10 and Windows 11 builds. Its primary interface is the embedded
[Universal-TUI](third_party/universal-tui/README.md) module.

> [!IMPORTANT]
> This is a development preview, not a finished release. The default resolver
> fails closed unless Microsoft symbols identify the exact function. Always run
> Diagnostics or Dry run before Apply on a new Windows flight.

## Scope

The modern backend targets the Insider/evaluation desktop build text rendered
by `shell32!CDesktopWatermark::s_DesktopBuildPaint`.

- It **does not** remove the "Activate Windows" watermark.
- It does not activate Windows or change licensing state.
- It intentionally leaves Test Mode, Safe Mode, Secure Boot, and security
  warnings alone.
- It never replaces Windows files, changes a system COM registration, takes
  ownership of a registry key, or weakens an ACL.

There is no supported Windows API for hiding this private shell UI. This tool is
therefore inherently version-sensitive. Unknown or ambiguous targets are
rejected without changing memory.

## What changed from the 2015 release

The original Delphi installer and ExplorerFrame proxy remain in `installer/`
and `proxy/` for historical reference only. They are excluded from the modern
build. The new implementation:

- uses a native C11 console executable and Universal-TUI as the main UI;
- reads the real OS build with `RtlGetVersion` and the process architecture with
  `IsWow64Process2`;
- identifies the current session's Explorer and its loaded `shell32.dll` rather
  than assuming a path or process;
- requires an exact Microsoft PDB GUID/age and symbol, then verifies that the
  loaded PE identity and target bytes match the on-disk module;
- can report an experimental x64 structural candidate for diagnostics, but
  never uses that heuristic for Apply;
- opens Explorer with only query/read/write/VM-operation rights instead of
  `PROCESS_ALL_ACCESS`;
- saves the original instruction bytes before changing memory and restores only
  when the PID, image identity, RVA, and current bytes still match;
- restores executable page protection, preserves CFG call-target metadata, and
  flushes the instruction cache;
- checks Explorer's dynamic-code mitigation and never disables a protection;
- offers reversible per-user startup through `HKCU` only.

The memory change is temporary. Restarting Explorer or signing out removes it.

## Target matrix

The code targets native x64 and ARM64 builds with NT build 19041 or newer. The
compatibility target list (not a claim that every combination is validated on
every commit) is:

- Windows 10 22H2 / ESU (19045) and LTSC 2021 (19044), x64;
- Windows 11 23H2 (22631), 24H2/LTSC 2024 (26100), and 25H2 (26200), x64/ARM64;
- Windows 11 26H1 (28000 family), x64/ARM64 where available;
- current Insider branches, including parallel 262xx/263xx/280xx families.

Build numbers are diagnostics, not a compatibility shortcut. The exact
`shell32.dll` image, PDB GUID/age, exact symbol, executable range, and live
bytes decide whether Apply is allowed. Apply is symbol-only on both x64 and
ARM64; the experimental offline candidate is x64 diagnostics only.

## Build

Requirements:

- Visual Studio 2022 with the Desktop development with C++ workload;
- Windows 10/11 SDK;
- CMake 3.24 or newer.

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

For ARM64, configure with `-A ARM64`. GitHub Actions uses native x64 and ARM64
Windows runners. Both execute the PE bounds tests and inspect their own
`shell32.dll` read-only, including exact Microsoft-PDB symbol resolution.
Release qualification on the target Windows families still requires
real-machine Diagnostics and Dry run checks.

## Use

Run `uwd.exe` in Windows Terminal or conhost. Select an action, review the
resolver settings, and choose **Save** to execute. Exit without saving cancels.

Useful non-interactive commands:

```text
uwd.exe --diagnostics
uwd.exe --apply --dry-run
uwd.exe --apply
uwd.exe --restore
uwd.exe --enable-startup
uwd.exe --disable-startup
```

If a brand-new Insider flight's PDB is not available yet, Apply fails safely.
On x64, maintainers can inspect the experimental heuristic candidate with:

```text
uwd.exe --diagnostics --experimental-offline-scan
```

The candidate is never used for Apply. During development on Windows build
26300 with `shell32.dll` 26100.8951, the heuristic produced a unique but wrong
RVA when compared with Microsoft's exact PDB. That validation is why symbol
identity is mandatory rather than merely preferred.

Diagnostics may download and cache the exact Microsoft PDB. `--offline` never
contacts the symbol server. `--dry-run` uses an existing cache only and makes no
memory, registry, state, or cache change.

Runtime state and the Universal-TUI config are stored under:

```text
%LOCALAPPDATA%\UniversalWatermarkDisabler
```

Rollback records are integrity-checked and scoped by interactive session so
multi-session Windows hosts cannot overwrite another session's recovery data.

## Universal-TUI module

`third_party/universal-tui` is a pinned vendored module from
`ayanami770/Universal-TUI` commit
`419fef2e89e68873fe969ecbdb02d8cfa2331ba3`. The upstream repository is
currently private. Vendoring keeps this public fork and its CI reproducible;
the directory can be converted to a git submodule after upstream is public.

Universal-TUI is Apache-2.0 licensed. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the component's
[LICENSE](third_party/universal-tui/LICENSE).

## Acknowledgements and license

The repository is MIT licensed. The modern implementation keeps the original
project history and credits. Its diagnostics-only structural locator is inspired by
the MIT-licensed [UWD3](https://github.com/jcnnik/uwd3); no AGPL UWD2 source was
copied.

See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
