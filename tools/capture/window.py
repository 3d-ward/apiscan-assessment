"""Application-window screenshot capture.

EXTRACTED CAPABILITY (CAP-018, CAP-019).

Captures ONE named application window, resolved by window id. Screen capture
and region capture are deliberately NOT implemented anywhere in this module,
and that is a safety property rather than an omission: an early version of the
source tool used full-screen capture and pulled an unrelated application window
into a client deliverable. Binding capture to a window id means nothing else on
the desktop can be included, even when another window overlaps the target.

STATUS IN THIS ENVIRONMENT: NOT VERIFIED. The window-id resolution requires
pyobjc (Quartz), which is not installed, and the framework is operating under a
no-download policy. The logic below is unit-tested against synthetic window
lists; the actual capture path has not been executed. Install with:

    python3 -m pip install pyobjc-framework-Quartz Pillow

It is also macOS-only and needs Screen Recording consent for the terminal.
Prefer ``tools/capture/render.py`` wherever the proxy UI itself is not the
point of the evidence: it is portable, unattended-safe and needs no consent.
"""
import os
import platform
import shutil
import subprocess


class CaptureUnavailable(Exception):
    """Window capture cannot run here. Carries the reason and the remedy."""

    def __init__(self, reason, remedy=""):
        self.reason = reason
        self.remedy = remedy
        super(CaptureUnavailable, self).__init__(
            reason + ((" Remedy: " + remedy) if remedy else ""))


def availability():
    """What is and is not available, without raising."""
    quartz = True
    try:
        import Quartz                        # noqa: F401
    except ImportError:
        quartz = False
    return {
        "platform": platform.system(),
        "supported_platform": platform.system() == "Darwin",
        "quartz": quartz,
        "screencapture": bool(shutil.which("screencapture")),
        "pillow": _pillow(),
        "usable": (platform.system() == "Darwin" and quartz
                   and bool(shutil.which("screencapture"))),
        "remedy": "python3 -m pip install pyobjc-framework-Quartz Pillow",
    }


def _pillow():
    try:
        import PIL                           # noqa: F401
        return True
    except ImportError:
        return False


def select_main_window(windows, owner_name):
    """Choose the main window of *owner_name* from a window list.

    Pure function so it is testable without Quartz. *windows* is a list of
    dicts shaped like Quartz's CGWindowListCopyWindowInfo output.

    The largest layer-0 window is chosen deliberately: settings panels, tool
    tips and dialogs belong to the same owner, and grabbing one of those
    produces a screenshot that evidences nothing.
    """
    candidates = []
    for w in windows or []:
        if w.get("kCGWindowOwnerName") != owner_name:
            continue
        if w.get("kCGWindowLayer") != 0:
            continue
        bounds = w.get("kCGWindowBounds") or {}
        area = int(bounds.get("Width", 0)) * int(bounds.get("Height", 0))
        if area <= 0:
            continue
        candidates.append({
            "area": area,
            "id": w.get("kCGWindowNumber"),
            "name": w.get("kCGWindowName") or "",
            "x": int(bounds.get("X", 0)), "y": int(bounds.get("Y", 0)),
            "width": int(bounds.get("Width", 0)),
            "height": int(bounds.get("Height", 0)),
        })
    if not candidates:
        return None
    candidates.sort(key=lambda c: (-c["area"], str(c["id"])))
    return candidates[0]


def list_windows():
    """Live window list. Requires Quartz."""
    try:
        import Quartz
    except ImportError:
        raise CaptureUnavailable(
            "pyobjc (Quartz) is not installed, so window ids cannot be "
            "resolved", "python3 -m pip install pyobjc-framework-Quartz")
    opts = (Quartz.kCGWindowListOptionOnScreenOnly
            | Quartz.kCGWindowListExcludeDesktopElements)
    return Quartz.CGWindowListCopyWindowInfo(opts, Quartz.kCGNullWindowID) or []


def find_window(owner_name):
    """Resolve the main window of *owner_name*, or raise CaptureUnavailable."""
    if platform.system() != "Darwin":
        raise CaptureUnavailable(
            "window capture is implemented for macOS only (this host is %s)"
            % platform.system(),
            "use tools/capture/render.py, which is portable")
    window = select_main_window(list_windows(), owner_name)
    if window is None:
        raise CaptureUnavailable(
            "no on-screen window found for %r -- is the application running "
            "and visible?" % owner_name)
    return window


def activate(app_name):
    subprocess.run(["osascript", "-e",
                    'tell application "%s" to activate' % app_name],
                   capture_output=True)


def capture(out_path, owner_name, activate_first=True):
    """Capture that one window. Returns (ok, detail).

    Uses ``screencapture -l <window-id>``, which captures the contents of that
    window alone. No screen or region capture path exists in this module.
    """
    avail = availability()
    if not avail["usable"]:
        missing = [k for k in ("supported_platform", "quartz", "screencapture")
                   if not avail[k]]
        return False, ("window capture unavailable (missing: %s). %s"
                       % (", ".join(missing), avail["remedy"]))
    if activate_first:
        activate(owner_name)
    try:
        window = find_window(owner_name)
    except CaptureUnavailable as exc:
        return False, str(exc)

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    proc = subprocess.run(
        ["screencapture", "-x", "-o", "-t", "png", "-l", str(window["id"]),
         out_path], capture_output=True, text=True)
    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        return True, ("captured window %s (%dx%d) %r"
                      % (window["id"], window["width"], window["height"],
                         window["name"][:48]))
    return False, ("screencapture produced no file: %s"
                   % (proc.stderr or "").strip()[:200])
