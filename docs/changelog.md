# Changelog

## 2.0.0-dev (2026)

- Replaced the unreproducible Delphi/VCL installer as the primary UI with a
  C11 console application powered by the Universal-TUI module.
- Replaced the default ExplorerFrame COM proxy with a fail-closed, current-
  session memory backend. The legacy source remains for historical reference.
- Added exact Microsoft-PDB resolution and live/disk byte verification. An
  x64 structural locator is retained for diagnostics only after validation
  demonstrated that a unique heuristic match can still be the wrong function.
- Added x64 and ARM64 build targets, modern Windows version/architecture
  detection, mitigation checks, SHA-256-protected session-scoped rollback
  state, and reversible per-user startup.
- Added CMake, PE-parser bounds tests, exact-PDB integration checks, and native
  Windows x64/ARM64 GitHub Actions.

## 1.0.0.6 (2015)

- Re-order initialize hooks.

## 1.0.0.5

- Improved method of detecting the watermark lines.

## 1.0.0.4

- An updated method of detecting the watermark lines.
- Fixed removed text in the Copy dialog.
- Fixed watermark text handling routines, it will not be messed up with other text any more.
- Added support for Windows 10 build 10031 and above.

## 1.0.0.0-1.0.0.3 (2014)

- Inject and hook tests.
