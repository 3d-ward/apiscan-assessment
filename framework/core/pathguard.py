"""Keep engagement data out of the framework tree.

The framework is reusable, releasable code. Evidence, findings and reports are
client data. Mixing them is the single most likely way confidential material
ends up in a shared repository, so the separation is enforced here rather than
left to convention.

A guard also refuses paths inside a declared *source* tree, which stops a
reconstructed tool from reading or writing the original project it came from.
"""
import os

from .errors import PathGuardError

FRAMEWORK_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def canonical(path):
    """Absolute, symlink-resolved, normalised path.

    Resolution matters: a symlink inside an otherwise-innocent directory could
    otherwise point back into the framework and defeat the containment check.
    """
    return os.path.realpath(os.path.abspath(os.path.expanduser(str(path))))


def is_within(child, parent):
    """True if *child* is *parent* or lies beneath it, after canonicalisation."""
    c, p = canonical(child), canonical(parent)
    if c == p:
        return True
    return c.startswith(p.rstrip(os.sep) + os.sep)


def assert_outside_framework(path, what="path"):
    """Refuse a path that resolves inside the framework tree."""
    if is_within(path, FRAMEWORK_ROOT):
        raise PathGuardError(
            "%s resolves inside the framework tree (%s -> %s). Engagement data "
            "must live in an engagement directory outside the framework."
            % (what, path, canonical(path)))
    return canonical(path)


def assert_outside(path, forbidden_roots, what="path"):
    """Refuse a path inside the framework or any of *forbidden_roots*."""
    resolved = assert_outside_framework(path, what)
    for root in forbidden_roots or ():
        if root and is_within(resolved, root):
            raise PathGuardError(
                "%s resolves inside a forbidden root (%s -> %s, forbidden: %s)"
                % (what, path, resolved, canonical(root)))
    return resolved


def ensure_engagement_dir(path, forbidden_roots=None, create=True):
    """Validate (and optionally create) a directory for engagement output."""
    resolved = assert_outside(path, forbidden_roots, what="engagement directory")
    if create:
        os.makedirs(resolved, exist_ok=True)
    elif not os.path.isdir(resolved):
        raise PathGuardError("engagement directory does not exist: %s" % resolved)
    return resolved


# -- destination validation ---------------------------------------------
#
# ENGINEERING IMPROVEMENT (review finding: "validate resolved file
# destinations before writing").
#
# Several identifiers reach a filesystem path by string interpolation: a case
# id becomes "<case>.req.txt", a run id becomes a directory, a snapshot
# manifest supplies a relative path, an intake candidate names a file to
# write. Each of those is data, and some of it is operator- or file-supplied
# rather than framework-generated (``--ids``, an imported corpus JSON, a
# register entry, a results.json row). Interpolating an unvalidated identifier
# into a path is how a write escapes the directory it was meant for.
#
# Two primitives, used everywhere a name becomes a path:
#
#   safe_component  one path segment, rejected unless it is plainly a name
#   safe_join       a join whose result is proven to stay under its base
#
# Both reject Windows-shaped escapes (backslash separators, drive letters,
# reserved device names) regardless of the host platform, because a path that
# is inert on POSIX can escape on Windows and evidence travels between them.

#: Conservative allowlist. Letters, digits and the three separators the
#: framework's own identifiers use. Anything else is refused rather than
#: sanitised: silently rewriting a name produces two cases that collide on one
#: filename, which corrupts evidence instead of refusing it.
_SAFE_COMPONENT = None

#: Windows reserved device names. A file called "NUL" or "CON" cannot be
#: created on Windows, and a path containing one behaves unpredictably.
WINDOWS_RESERVED = frozenset([
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
])

MAX_COMPONENT_LENGTH = 120


def _component_pattern():
    global _SAFE_COMPONENT
    if _SAFE_COMPONENT is None:
        import re
        # A leading underscore is ordinary and must be allowed: the framework
        # itself is full of ``__init__.py``, and an intake candidate or a
        # snapshot manifest legitimately names those. A leading DOT stays
        # refused (hidden files, and ``..``), and so does a leading HYPHEN,
        # which a shell or a command-line tool can read as a flag.
        _SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
    return _SAFE_COMPONENT


def safe_component(name, what="name"):
    """Return *name* if it is a single, plainly-safe path component.

    Refuses: empty values, ``.`` and ``..``, anything containing a POSIX or
    Windows separator, NUL and control characters, drive letters, leading
    dots and dashes, Windows reserved device names, over-long names, and any
    character outside ``[A-Za-z0-9._-]``.

    Raises PathGuardError rather than sanitising, because a sanitised name can
    collide with another sanitised name and silently overwrite its evidence.
    """
    text = str(name)
    if not text:
        raise PathGuardError("%s is empty; it cannot be used as a filename"
                             % what)
    if len(text) > MAX_COMPONENT_LENGTH:
        raise PathGuardError(
            "%s is %d characters, over the %d-character limit for a path "
            "component (%r...)"
            % (what, len(text), MAX_COMPONENT_LENGTH, text[:40]))
    if text in (".", ".."):
        raise PathGuardError("%s is %r, which traverses the directory tree"
                             % (what, text))
    for bad, label in (("/", "a POSIX path separator"),
                       ("\\", "a Windows path separator"),
                       ("\x00", "a NUL byte")):
        if bad in text:
            raise PathGuardError(
                "%s %r contains %s; a name that becomes a path must be a "
                "single component" % (what, text[:60], label))
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise PathGuardError(
            "%s %r contains a control character" % (what, text[:60]))
    if len(text) >= 2 and text[1] == ":":
        raise PathGuardError(
            "%s %r looks like a Windows drive-qualified path" % (what, text))
    if text.split(".")[0].upper() in WINDOWS_RESERVED:
        raise PathGuardError(
            "%s %r is a Windows reserved device name and cannot be a file"
            % (what, text))
    if not _component_pattern().match(text):
        raise PathGuardError(
            "%s %r is not a safe path component; allowed characters are "
            "letters, digits, dot, underscore and hyphen, and it must not "
            "start with a dot or a hyphen" % (what, text[:60]))
    return text


def safe_join(base, *parts, **kw):
    """Join *parts* onto *base* and prove the result stays under *base*.

    Every part is validated as a single component, so this both constrains the
    shape of each name and verifies the canonicalised result -- symlinks
    resolved -- is still contained. The containment check is the one that
    matters when a component is a directory that is itself a symlink.
    """
    what = kw.pop("what", "path")
    if kw:
        raise TypeError("unexpected keyword argument(s): %s"
                        % ", ".join(sorted(kw)))
    base_resolved = canonical(base)
    for part in parts:
        safe_component(part, what=what)
    candidate = os.path.join(base_resolved, *[str(p) for p in parts])
    if not is_within(candidate, base_resolved):
        raise PathGuardError(
            "%s resolves outside its base directory (%s -> %s, base %s)"
            % (what, os.path.join(*[str(p) for p in parts]),
               canonical(candidate), base_resolved))
    return candidate


def safe_relative_join(base, relative, what="path"):
    """Join a multi-segment *relative* path onto *base*, validating each segment.

    For callers that legitimately handle nested relative paths read from a
    manifest or a candidate change-set -- a snapshot tree, an intake staging
    set -- where the path has several segments but still must not escape.
    """
    text = str(relative).replace("\\", "/")
    if text.startswith("/") or (len(text) >= 2 and text[1] == ":"):
        raise PathGuardError(
            "%s %r is absolute; only a relative path inside %s is permitted"
            % (what, relative, base))
    segments = [s for s in text.split("/") if s not in ("", ".")]
    if not segments:
        raise PathGuardError("%s %r names no file" % (what, relative))
    return safe_join(base, *segments, what=what)
