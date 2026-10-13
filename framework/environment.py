"""What this build is, and what this host can actually do.

ENGINEERING IMPROVEMENT (review finding 5: "publish a version, commit
identifier, supported environments, known limitations, and actual test
results", and "distinguish environment-related test failures from product
defects").

Two different readers need this. A client reading a report needs to know which
build produced the evidence. A maintainer reading a bug report needs to know
whether a failure is a defect or a missing optional dependency on the
reporter's machine -- and those are indistinguishable without a statement of
what was present.

So every optional capability is probed here, once, and reported with the
consequence of its absence. The framework's rule is that an absent dependency
yields NOT VERIFIED rather than a pass; this module is where a human or a CI
job can see which of those are in play before the run rather than after.
"""
import os
import platform
import subprocess
import sys

#: Release version. Bumped by a maintainer as part of the release process in
#: RELEASE.md; the test suite asserts it matches the top of the CHANGELOG.
VERSION = "1.1.0"

#: Environments the release process actually tests. Anything outside this is
#: unsupported rather than broken -- a distinction a bug report needs.
SUPPORTED_PYTHON = (3, 9)
SUPPORTED_ENVIRONMENTS = ("Linux and macOS on CPython 3.9 through 3.13; "
                          "Windows is best-effort and not release-tested")

FRAMEWORK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def commit():
    """The git commit this tree is at, or a statement that it is unknown.

    Never guesses. An unknown commit is reported as unknown, because a report
    citing the wrong commit is worse than one citing none.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", FRAMEWORK_ROOT, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return "unknown (git unavailable)"
    if proc.returncode != 0:
        return "unknown (not a git checkout)"
    sha = (proc.stdout or "").strip()
    try:
        dirty = subprocess.run(
            ["git", "-C", FRAMEWORK_ROOT, "status", "--porcelain"],
            capture_output=True, text=True, timeout=10)
        if (dirty.stdout or "").strip():
            return "%s+modified" % sha
    except (OSError, subprocess.SubprocessError):
        pass
    return sha


def _which(name):
    import shutil
    return shutil.which(name)


def _module(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def capabilities():
    """Each optional capability, whether it is available, and what is lost."""
    from tools.capture import render, window

    out = {}

    def add(name, available, detail, effect):
        out[name] = {
            "available": bool(available),
            "status": "available" if available else "ABSENT",
            "detail": detail,
            "effect_if_absent": effect,
        }

    add("curl", _which("curl"), _which("curl") or "not on PATH",
        "nothing works: curl is the transport")
    add("openssl", _which("openssl"), _which("openssl") or "not on PATH",
        "no transport-layer evidence can be captured at all")
    add("xlsx", _module("openpyxl"), "openpyxl",
        "the deliverable degrades to Markdown and CSV; a note is printed")
    add("poc_images", _module("PIL"), "Pillow",
        "PoC images are referenced by path instead of embedded in the "
        "workbook")
    browser = render.find_browser()
    add("png_render", browser, browser or "no Chrome/Chromium found",
        "PoC evidence is produced as a self-contained HTML artifact instead")
    win = window.availability()
    add("window_capture", win.get("usable"), str(win.get("detail", "")),
        "proxy-window screenshots are unavailable; use rendered evidence")
    ciphers = _which("nmap") or _which("testssl.sh") or _which("testssl")
    add("cipher_enumeration", ciphers, ciphers or "neither nmap nor testssl.sh",
        "cipher suites are reported NOT VERIFIED, never as a clean result")
    return out


def python_supported():
    return sys.version_info[:2] >= SUPPORTED_PYTHON


def describe():
    caps = capabilities()
    return {
        "name": "apiscan-assessment",
        "version": VERSION,
        "commit": commit(),
        "python": sys.version.split()[0],
        "python_supported": python_supported(),
        "platform": "%s %s (%s)" % (platform.system(), platform.release(),
                                    platform.machine()),
        "supported_environments": SUPPORTED_ENVIRONMENTS,
        "capabilities": caps,
        "absent_capabilities": sorted(k for k, v in caps.items()
                                      if not v["available"]),
    }


def evidence_stamp():
    """The one-line build statement that travels into run metadata."""
    info = describe()
    absent = info["absent_capabilities"]
    return ("apiscan-assessment %s (commit %s) on python %s / %s%s"
            % (info["version"], info["commit"], info["python"],
               info["platform"],
               "; capabilities absent: %s" % ", ".join(absent)
               if absent else ""))
