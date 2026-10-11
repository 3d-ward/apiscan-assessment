# Dependencies

## Core (required)

| Dependency | Why |
|---|---|
| Python 3.8+ | the framework itself; standard library only |
| `curl` | transport. Chosen over an HTTP library because `--trace-ascii` records the wire exchange including the TLS handshake, `--data-binary @file` sends malformed bodies byte-for-byte without repairing them, and proxy traversal matches a browser's |

There is no `requirements.txt` for the core loop because there are no core
third-party packages.

## Optional, with degradation

| Package / tool | Enables | Without it | Install |
|---|---|---|---|
| `openpyxl` | xlsx workbook | Markdown + CSV, with a printed note | `python3 -m pip install openpyxl` |
| `Pillow` | PoC images embedded in the workbook | image paths referenced instead; reported in `RenderResult.notes` | `python3 -m pip install Pillow` |
| Chrome / Chromium | PNG PoC rendering | self-contained HTML artifact | platform package |
| `pyobjc-framework-Quartz` | proxy-window screenshots (macOS) | unavailable; use rendered evidence | `python3 -m pip install pyobjc-framework-Quartz` |
| `nmap` or `testssl.sh` | TLS cipher enumeration | reported `NOT VERIFIED` with a remedy | platform package |

Install everything optional:

```bash
python3 -m pip install openpyxl Pillow pyobjc-framework-Quartz
```

On a system where `python3` and `pip3` resolve to different interpreters, always
use `python3 -m pip`. Packages installed by the wrong interpreter are not
importable, and the failure looks like a missing package rather than a wrong
one.

## The degradation contract

A capability whose dependency is absent must:

1. detect the absence before attempting the work;
2. report `NOT VERIFIED` (never a pass, never silence);
3. name the install command;
4. where possible, offer a reduced alternative.

`framework/core/errors.py` provides `DependencyUnavailable` carrying the
dependency, the capability and the install hint. Check availability with:

```bash
./apiscan preflight --profile <profile> --offline --all
```
