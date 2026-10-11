"""Framework snapshots and rollback.

Git is not in use in this installation, so rollback is provided by versioned
snapshots of the framework's own source. Phase 8 of the framework's governance
requires that an automatic improvement can always be undone; this is that
mechanism.

Snapshots are stored OUTSIDE the framework tree so they neither bloat the
release nor appear in the release manifest. Only source is copied -- evidence,
virtualenvs, caches and secrets are excluded by pattern, so a snapshot can
never become a backdoor route for client data into the framework.
"""
import datetime
import hashlib
import json
import os
import shutil

FRAMEWORK_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

DEFAULT_STORE = os.path.join(os.path.dirname(FRAMEWORK_ROOT),
                             "apiscan-assessment-audit", "snapshots")

EXCLUDE_DIRS = {".venv", "venv", "__pycache__", ".git", "evidence", "reports",
                "findings", "poc", "node_modules", ".pytest_cache"}
EXCLUDE_SUFFIX = (".pyc", ".pyo", ".png", ".jpg", ".jpeg", ".xlsx", ".docx",
                  ".pdf", ".p12", ".pfx", ".key", ".pem", ".crt", ".der")
EXCLUDE_NAMES = {".DS_Store", ".env"}


def _included(root, rel):
    parts = rel.split(os.sep)
    if any(p in EXCLUDE_DIRS for p in parts):
        return False
    name = parts[-1]
    if name in EXCLUDE_NAMES or name.startswith(".env"):
        return False
    return not name.endswith(EXCLUDE_SUFFIX)


def _walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if _included(root, rel):
                yield rel, full


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def create(label="manual", store=None, root=None):
    """Snapshot the framework source. Returns the snapshot directory."""
    root = root or FRAMEWORK_ROOT
    store = store or DEFAULT_STORE
    snap_id = "%s-%s" % (datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                         label.replace(os.sep, "-"))
    dest = os.path.join(store, snap_id)
    os.makedirs(dest, exist_ok=True)

    manifest = []
    for rel, full in _walk(root):
        target = os.path.join(dest, "tree", rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(full, target)
        manifest.append({"path": rel, "sha256": _sha256(full),
                         "bytes": os.path.getsize(full)})

    with open(os.path.join(dest, "manifest.json"), "w") as fh:
        json.dump({
            "id": snap_id, "label": label,
            "created": datetime.datetime.now().isoformat(timespec="seconds"),
            "framework_root": root, "file_count": len(manifest),
            "files": manifest,
        }, fh, indent=2)
    return dest


def listing(store=None):
    store = store or DEFAULT_STORE
    if not os.path.isdir(store):
        return []
    out = []
    for name in sorted(os.listdir(store)):
        mpath = os.path.join(store, name, "manifest.json")
        if not os.path.exists(mpath):
            continue
        with open(mpath) as fh:
            m = json.load(fh)
        out.append({"id": m["id"], "label": m.get("label", ""),
                    "created": m.get("created", ""),
                    "file_count": m.get("file_count", 0)})
    return out


def rollback(snapshot_id, store=None, root=None, safety_snapshot=True):
    """Restore a snapshot over the framework tree.

    A safety snapshot of the CURRENT state is taken first by default, so a
    rollback is itself reversible -- otherwise the first rollback destroys the
    only copy of whatever it replaced.
    """
    store = store or DEFAULT_STORE
    root = root or FRAMEWORK_ROOT
    src = os.path.join(store, snapshot_id, "tree")
    mpath = os.path.join(store, snapshot_id, "manifest.json")
    if not os.path.isdir(src) or not os.path.exists(mpath):
        raise ValueError("no such snapshot: %s (store %s)"
                         % (snapshot_id, store))
    if safety_snapshot:
        create("pre-rollback-%s" % snapshot_id, store, root)

    with open(mpath) as fh:
        manifest = json.load(fh)

    restored = 0
    for entry in manifest["files"]:
        s = os.path.join(src, entry["path"])
        d = os.path.join(root, entry["path"])
        if not os.path.exists(s):
            continue
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copy2(s, d)
        restored += 1
    return restored


def verify(snapshot_id, store=None):
    """Confirm a snapshot's stored files still match its manifest."""
    store = store or DEFAULT_STORE
    base = os.path.join(store, snapshot_id)
    with open(os.path.join(base, "manifest.json")) as fh:
        manifest = json.load(fh)
    problems = []
    for entry in manifest["files"]:
        path = os.path.join(base, "tree", entry["path"])
        if not os.path.exists(path):
            problems.append("%s: missing from the snapshot" % entry["path"])
        elif _sha256(path) != entry["sha256"]:
            problems.append("%s: hash mismatch" % entry["path"])
    return problems


def diff_against_current(snapshot_id, store=None, root=None):
    """What changed in the framework since *snapshot_id*."""
    store = store or DEFAULT_STORE
    root = root or FRAMEWORK_ROOT
    with open(os.path.join(store, snapshot_id, "manifest.json")) as fh:
        manifest = json.load(fh)
    snap = {e["path"]: e["sha256"] for e in manifest["files"]}
    current = {rel: _sha256(full) for rel, full in _walk(root)}
    added = sorted(set(current) - set(snap))
    removed = sorted(set(snap) - set(current))
    changed = sorted(p for p in set(snap) & set(current)
                     if snap[p] != current[p])
    return {"added": added, "removed": removed, "changed": changed}
