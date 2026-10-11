"""Evidence storage.

EXTRACTED CAPABILITY (CAP-013) with integrity added.

Layout, per run:

    <evidence_root>/<run_id>/
        run.json                 run metadata (target, proxy, operator, policy)
        <case>.req.txt           exact request body bytes sent
        <case>.resp.txt          status, headers and body as received
        <case>.trace.txt         wire-level trace, including the TLS handshake
        results.json             one record per case
        manifest.json            SHA-256 of every artifact in the run

ENGINEERING IMPROVEMENT over the source: a per-artifact SHA-256 manifest and a
run metadata record. Without them, evidence has no integrity statement -- a
client cannot tell whether the file in a report is the file that was captured,
and an assessor cannot prove a transcript was not edited after the fact.

The evidence root is validated by the path guard: it must lie outside the
framework tree. Client traffic does not belong in reusable code.
"""
import datetime
import hashlib
import json
import os

from ..core.pathguard import ensure_engagement_dir

RUN_ID_FORMAT = "%Y%m%d-%H%M%S"


def _utc_now():
    """Timezone-aware UTC timestamp.

    ``datetime.utcnow()`` is deprecated from Python 3.12 and returns a naive
    value, which makes evidence timestamps ambiguous about their zone -- not
    something a deliverable should be vague about.
    """
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def new_run_id(now=None):
    return (now or datetime.datetime.now()).strftime(RUN_ID_FORMAT)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class EvidenceStore(object):
    def __init__(self, evidence_root, run_id=None, forbidden_roots=None,
                 metadata=None):
        self.root = ensure_engagement_dir(evidence_root,
                                          forbidden_roots=forbidden_roots)
        self.run_id = run_id or new_run_id()
        self.run_dir = os.path.join(self.root, self.run_id)
        os.makedirs(self.run_dir, exist_ok=True)
        self.results = []
        self.metadata = dict(metadata or {})
        self.metadata.setdefault("run_id", self.run_id)
        self.metadata.setdefault("started_utc",
                                 _utc_now())

    # -- paths -----------------------------------------------------------
    def path(self, case_id, kind):
        return os.path.join(self.run_dir, "%s.%s.txt" % (case_id, kind))

    def request_path(self, case_id):
        return self.path(case_id, "req")

    def response_path(self, case_id):
        return self.path(case_id, "resp")

    def trace_path(self, case_id):
        return self.path(case_id, "trace")

    def relative(self, path):
        return os.path.relpath(path, self.root)

    # -- writing ---------------------------------------------------------
    def write_response(self, case_id, response):
        """Persist the response exactly as observed."""
        path = self.response_path(case_id)
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write("HTTP %s  (curl rc=%s)\n\n%s\n\n%s"
                     % (response.status, response.meta.get("curl_rc"),
                        response.headers or "", response.body or ""))
        return path

    def record(self, rec):
        self.results.append(rec)
        return rec

    def finalise(self):
        """Write results, metadata and the integrity manifest."""
        self.metadata["finished_utc"] = \
            _utc_now()
        self.metadata["case_count"] = len(self.results)
        with open(os.path.join(self.run_dir, "run.json"), "w") as fh:
            json.dump(self.metadata, fh, indent=2, sort_keys=True)
        with open(os.path.join(self.run_dir, "results.json"), "w") as fh:
            json.dump(self.results, fh, indent=2, default=str)

        entries = []
        for name in sorted(os.listdir(self.run_dir)):
            full = os.path.join(self.run_dir, name)
            if not os.path.isfile(full) or name == "manifest.json":
                continue
            entries.append({"file": name, "bytes": os.path.getsize(full),
                            "sha256": sha256_file(full)})
        manifest = {
            "run_id": self.run_id,
            "generated_utc": _utc_now(),
            "artifact_count": len(entries),
            "artifacts": entries,
            # Artifacts produced AFTER the run by a later offline command --
            # re-classification output, for example. Kept separate from
            # ``artifacts`` so the captured set stays exactly what the run
            # observed, while derived files are still hashed and still
            # tamper-checked.
            "derived": [],
        }
        mpath = os.path.join(self.run_dir, "manifest.json")
        with open(mpath, "w") as fh:
            json.dump(manifest, fh, indent=2)

        pointer = os.path.join(self.root, "latest-run.txt")
        with open(pointer, "w") as fh:
            fh.write(self.run_dir + "\n")
        return manifest

    # -- derived artifacts -----------------------------------------------
    @staticmethod
    def register_derived(run_dir, filename):
        """Record a post-run artifact in the run manifest, and hash it.

        ENGINEERING IMPROVEMENT. An offline command that writes into a run
        directory -- ``reclassify`` is the one that does -- otherwise leaves a
        file ``verify`` reports as "present but not in manifest", so running a
        documented read-only command breaks the run's integrity check for good.
        A derived artifact is recorded separately from the captured set, with
        its own timestamp, and is hashed like any other: tamper detection still
        applies to it.
        """
        full = os.path.join(run_dir, filename)
        if not os.path.isfile(full):
            raise FileNotFoundError(
                "cannot register derived artifact %r: no such file in %s"
                % (filename, run_dir))
        mpath = os.path.join(run_dir, "manifest.json")
        with open(mpath) as fh:
            manifest = json.load(fh)
        entry = {"file": filename, "bytes": os.path.getsize(full),
                 "sha256": sha256_file(full), "registered_utc": _utc_now()}
        derived = [d for d in manifest.get("derived", [])
                   if d.get("file") != filename]
        derived.append(entry)
        manifest["derived"] = sorted(derived, key=lambda d: d["file"])
        with open(mpath, "w") as fh:
            json.dump(manifest, fh, indent=2)
        return manifest

    # -- verification ----------------------------------------------------
    @staticmethod
    def verify(run_dir):
        """Re-hash a run and report drift against its manifest."""
        mpath = os.path.join(run_dir, "manifest.json")
        with open(mpath) as fh:
            manifest = json.load(fh)
        problems = []
        for entry in (list(manifest["artifacts"])
                      + list(manifest.get("derived", []))):
            full = os.path.join(run_dir, entry["file"])
            if not os.path.exists(full):
                problems.append("%s: missing" % entry["file"])
                continue
            actual = sha256_file(full)
            if actual != entry["sha256"]:
                problems.append("%s: hash mismatch (manifest %s, actual %s)"
                                % (entry["file"], entry["sha256"][:16],
                                   actual[:16]))
        listed = {e["file"] for e in manifest["artifacts"]}
        listed |= {e["file"] for e in manifest.get("derived", [])}
        for name in os.listdir(run_dir):
            if name not in listed and name != "manifest.json" \
                    and os.path.isfile(os.path.join(run_dir, name)):
                problems.append("%s: present but not in manifest" % name)
        return problems


def find_latest_run(evidence_root):
    pointer = os.path.join(evidence_root, "latest-run.txt")
    if os.path.exists(pointer):
        with open(pointer) as fh:
            candidate = fh.read().strip()
        if candidate and os.path.isdir(candidate):
            return candidate
    runs = sorted(d for d in os.listdir(evidence_root)
                  if os.path.isdir(os.path.join(evidence_root, d))
                  and d[:1].isdigit())
    if not runs:
        return None
    return os.path.join(evidence_root, runs[-1])
