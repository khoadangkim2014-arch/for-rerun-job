# Third-party notices

## Universal-TUI

- Upstream: `https://github.com/ayanami770/Universal-TUI`
- Pinned commit: `419fef2e89e68873fe969ecbdb02d8cfa2331ba3`
- License: Apache License 2.0
- Local copy: `third_party/universal-tui`

The upstream repository was private when this public fork was prepared.
`utui.c`, `utui.h`, its README, and its unmodified license are vendored so a
normal clone and GitHub Actions build remain reproducible. The UWD integration
code is separate and does not relicense Universal-TUI under MIT.

## UWD3 structural-locator acknowledgement

- Project: `https://github.com/jcnnik/uwd3`
- License: MIT

The diagnostics-only x64 structural locator was independently implemented in C after
studying UWD3's public description of the SetTextColor/IAT/.pdata technique.
The implementation adds strict bounds checks, requires a unique `.pdata`
function, and is opt-in. It is never authorized to patch memory because a
current Windows validation found a unique candidate that differed from the
exact Microsoft PDB symbol. No source
from the AGPL-licensed UWD2 project was copied.
