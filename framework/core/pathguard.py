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
