# Setup

## Requirements

**Required:** Python 3.8 or later, and `curl` on `PATH`. That is the whole core
dependency set -- the framework uses only the standard library otherwise.

**Optional**, each degrading gracefully when absent:

| Package / tool | Enables | Install |
|---|---|---|
| `openpyxl` | spreadsheet report | `python3 -m pip install openpyxl` |
| `Pillow` | PoC images embedded in the workbook | `python3 -m pip install Pillow` |
| Chrome / Chromium | PNG PoC rendering | platform package |
| `pyobjc-framework-Quartz` | proxy-window capture (macOS only) | `python3 -m pip install pyobjc-framework-Quartz` |
| `nmap` or `testssl.sh` | TLS cipher enumeration | platform package |

Check what is available:

```bash
./apiscan preflight --profile <profile> --offline --all
```

## Install

No build step. Clone or copy the tree and run `./apiscan`.

To put it on `PATH`, symlink the wrapper -- it resolves its own location, so a
symlink works:

```bash
ln -s /path/to/apiscan-assessment/apiscan ~/.local/bin/apiscan
```

### Optional virtual environment

```bash
python3 -m venv .venv
.venv/bin/python -m pip install openpyxl Pillow
APISCAN_PYTHON=.venv/bin/python ./apiscan preflight --profile <p> --offline
```

Note: on systems where `python3` and `pip3` resolve to *different* Python
installations, always use `python3 -m pip`, never bare `pip3`. Packages
installed by the wrong interpreter will not be importable.

## Verify the installation

```bash
python3 -m unittest discover -s tests -t . -p "test_*.py"
```

Expect every test to pass. One test is skipped when `openpyxl` is absent.

## Proxy setup (optional)

Set `transport.proxy` in the profile. Then:

1. Make sure request interception is **off** -- with it on, every case queues
   waiting to be forwarded, the client times out, and the proxy records history
   rows with no response. `./apiscan preflight` detects this with a timing probe.
2. If the target enforces mutual TLS, configure the client certificate **inside
   the proxy**, and set `transport.client_cert.mode` to `"proxy"`. The proxy
   terminates TLS and performs the upstream handshake, so a certificate passed
   to the HTTP client never reaches the server.
3. Optionally fetch the proxy CA and set `tls_verify.mode` to `"ca"` so the
   client verifies the proxy strictly instead of disabling verification.

## Environment isolation

Nothing in this framework writes outside the paths you supply. Evidence,
reports and credentials go in the engagement directory, which must live outside
the framework tree -- the path guard enforces this.
