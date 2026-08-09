# Vendored upstream

- Repository: `https://github.com/ayanami770/Universal-TUI`
- Commit: `419fef2e89e68873fe969ecbdb02d8cfa2331ba3`
- Vendored on: 2026-08-09

The repository was private at vendoring time. The upstream `README.md` and
`LICENSE` are included without changes. The vendored `utui.c` and `utui.h`
carry clearly marked UWD integration changes dated 2026-08-09:

- an opt-in `UtApp.exit_after_save` mode so a successful Save can return from
  `ut_run()` with result 1; and
- propagation of mouse-button exit results to the main event loop.

It is compiled as a distinct strict ISO C99 static library by the top-level
CMake project.

When the upstream repository becomes public, the local changes should be
submitted upstream before this directory is replaced by a pinned submodule.
