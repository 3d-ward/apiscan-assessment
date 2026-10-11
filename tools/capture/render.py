"""Evidence rendering: captured bytes to an image.

EXTRACTED CAPABILITY (CAP-016).

This is the primary PoC path and it is deliberately the safe one. It rasterises
the verbatim captured request and response bytes through a headless browser. It
touches no screen-capture API at all, so the image can contain only the
evidence -- nothing else on the operator's desktop can leak into a client
deliverable, and it is safe to run unattended in a batch.

Two details are load-bearing and were learned the hard way in the source:

  * An ISOLATED browser profile directory is mandatory. Without it, headless
    Chrome contends with an already-running Chrome for the default profile lock
    and hangs indefinitely, stalling any batch that calls this.
  * The provenance footer is a REQUIRED argument, not a default. A defaulted
    provenance string is precisely how evidence ends up asserting a capture
    path that did not happen -- see ``framework/evidence/provenance.py``.

ENGINEERING IMPROVEMENT: a standalone HTML output path that needs no browser at
all, so the capability degrades to a self-contained, printable artifact instead
of failing when no Chrome is installed.
"""
import html as _html
import os
import shutil
import subprocess
import tempfile

CHROME_CANDIDATES = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome-stable",
    "google-chrome",
    "chromium",
    "chromium-browser",
)

MAX_FILE_CHARS = 8000

CSS = """
:root{color-scheme:dark}
body{margin:0;background:#15161c;color:#e7e7f0;
     font:13px/1.55 ui-monospace,'SF Mono',Menlo,Consolas,monospace;padding:28px}
h1{font:600 18px/1.35 -apple-system,'Segoe UI',system-ui,sans-serif;
   margin:0 0 6px;color:#fff;letter-spacing:-.01em}
.sub{font:12px/1.5 -apple-system,'Segoe UI',system-ui,sans-serif;
     color:#9b9bb2;margin:0 0 22px}
.f{margin:0 0 18px;border:1px solid #32334a;border-radius:7px;overflow:hidden}
.fh{background:#232432;padding:8px 13px;
    font:600 11px -apple-system,'Segoe UI',system-ui,sans-serif;
    color:#b6b6cf;letter-spacing:.5px;text-transform:uppercase}
pre{margin:0;padding:13px;white-space:pre-wrap;word-break:break-word;
    background:#101118}
.hl{color:#ff8d6b;font-weight:600}
.foot{font:11px/1.6 -apple-system,'Segoe UI',system-ui,sans-serif;
      color:#7b7b96;margin-top:20px;border-top:1px solid #32334a;
      padding-top:11px}
.meta{color:#6f6f8a}
"""


def find_browser():
    for candidate in CHROME_CANDIDATES:
        if os.path.isabs(candidate):
            if os.path.exists(candidate):
                return candidate
        else:
            found = shutil.which(candidate)
            if found:
                return found
    return None


def headline_title(case_id, description, limit=90):
    """``<case id> -- <description>``, trimmed on a word boundary.

    A bare ``description[:90]`` lands mid-word, and this string is the heading
    of a client-facing PoC image. The case id is never sacrificed: it is what
    ties the exhibit back to the test log.
    """
    prefix = "%s -- " % case_id
    room = limit - len(prefix)
    text = (description or "").strip()
    if room <= 0:
        return prefix.rstrip()[:limit]
    if len(text) <= room:
        return prefix + text
    clipped = text[:room - 3]
    spaced = clipped.rsplit(" ", 1)[0] if " " in clipped else clipped
    return prefix + spaced.rstrip(" ,;:-") + "..."


def build_html(title, files, provenance, subtitle="", highlight=None,
               root=None):
    """Assemble the evidence document. Pure -- no I/O beyond reading *files*."""
    if not provenance:
        raise ValueError(
            "provenance is required: evidence must state how it was captured, "
            "and a defaulted provenance line is how an artifact ends up "
            "asserting a capture path that did not happen")
    highlight = list(highlight or [])
    blocks = []
    for path in files:
        label = os.path.relpath(path, root) if root else os.path.basename(path)
        try:
            with open(path, "r", errors="replace") as fh:
                text = fh.read().rstrip()
        except (IOError, OSError) as exc:
            text = "<unreadable: %s>" % exc
        truncated = len(text) > MAX_FILE_CHARS
        if truncated:
            text = text[:MAX_FILE_CHARS] + "\n... [truncated for display] ..."
        escaped = _html.escape(text)
        for term in highlight:
            if not term:
                continue
            esc_term = _html.escape(term)
            escaped = escaped.replace(
                esc_term, '<span class="hl">%s</span>' % esc_term)
        blocks.append(
            '<div class="f"><div class="fh">%s%s</div><pre>%s</pre></div>'
            % (_html.escape(label),
               " &middot; truncated" if truncated else "", escaped))

    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>%s</title><style>%s</style></head><body>"
        "<h1>%s</h1><div class='sub'>%s</div>%s"
        "<div class='foot'>%s</div></body></html>"
        % (_html.escape(title), CSS, _html.escape(title),
           _html.escape(subtitle), "".join(blocks),
           _html.escape(provenance)))


def content_lines(files, width=150):
    """Rendered line count, accounting for wrapping of long lines."""
    total = 0
    for path in files:
        try:
            with open(path, "r", errors="replace") as fh:
                text = fh.read().rstrip()[:MAX_FILE_CHARS]
        except (IOError, OSError):
            total += 1
            continue
        for line in text.splitlines() or [""]:
            total += max(1, (len(line) + width - 1) // width)
    return total


def estimate_height(files, blocks, width=150):
    """Size the canvas to the content.

    Measured from the evidence itself rather than from the HTML source: an
    earlier version counted characters in the markup, which is dominated by
    the stylesheet and produced a canvas with a large empty region below the
    evidence.
    """
    lines = content_lines(files, width)
    header = 112          # title + subtitle
    per_block = 74        # block header, padding and margin
    footer = 76
    return max(300, min(6000,
                        header + footer + lines * 21 + per_block * max(1, blocks)))


def write_html(out_path, title, files, provenance, subtitle="",
               highlight=None, root=None):
    """Write a self-contained HTML artifact. Needs no browser."""
    doc = build_html(title, files, provenance, subtitle, highlight, root)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return out_path


def render_png(out_path, title, files, provenance, subtitle="",
               highlight=None, root=None, width=1200, timeout=60):
    """Rasterise the evidence to a PNG via a headless browser.

    Returns (ok, detail). Never raises for a missing browser: the caller
    degrades to ``write_html`` and records NOT VERIFIED.
    """
    browser = find_browser()
    if not browser:
        return False, ("no Chrome or Chromium binary found; use write_html() "
                       "for a browser-free artifact, or install one of: %s"
                       % ", ".join(CHROME_CANDIDATES[:3]))

    doc = build_html(title, files, provenance, subtitle, highlight, root)
    height = estimate_height(files, len(files))

    tmp_html = tempfile.NamedTemporaryFile("w", suffix=".html", delete=False,
                                           encoding="utf-8")
    tmp_html.write(doc)
    tmp_html.close()
    # An isolated profile directory is REQUIRED. Without it headless Chrome
    # contends with a running Chrome for the default profile lock and hangs
    # forever, stalling the whole batch.
    profile_dir = tempfile.mkdtemp(prefix="apiscan-render-")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    try:
        proc = subprocess.run(
            [browser, "--headless=new", "--disable-gpu", "--no-sandbox",
             "--user-data-dir=" + profile_dir, "--no-first-run",
             "--disable-extensions", "--disable-sync", "--hide-scrollbars",
             "--force-device-scale-factor=2",
             "--window-size=%d,%d" % (width, height),
             "--screenshot=" + out_path, "file://" + tmp_html.name],
            capture_output=True, text=True, timeout=timeout)
        stderr = (proc.stderr or "")[-300:]
    except subprocess.TimeoutExpired:
        stderr = "browser timed out after %ss" % timeout
    except OSError as exc:
        stderr = str(exc)
    finally:
        shutil.rmtree(profile_dir, ignore_errors=True)
        try:
            os.unlink(tmp_html.name)
        except OSError:
            pass

    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        return True, "rendered %s (%d bytes)" % (out_path,
                                                 os.path.getsize(out_path))
    return False, "render failed: %s" % stderr.strip()
