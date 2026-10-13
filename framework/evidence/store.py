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

from ..core.pathguard import ensure_engagement_dir, safe_component, safe_join

RUN_ID_FORMAT = "%Y%m%d-%H%M%S"

#: Default retention for raw evidence, in days. An engagement may shorten or
#: lengthen it; what it may not do is leave it unstated, because "indefinite"
#: is what happens to client data nobody assigned a lifetime to.
DEFAULT_RETENTION_DAYS = 90


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


#: Evidence-file envelope version. The format declares the exact length of
#: each section, so the sections cannot be relocated by their own content.
ENVELOPE_MAGIC = "APISCAN-EVIDENCE/1"

SECTION_SEP = "\n\n"

#: Owner-only. Evidence carries credentials in trace files, identifiers and
#: personal data in bodies; the default umask does not.
DIR_MODE = 0o700
FILE_MODE = 0o600


def restrict(path):
    """Owner-only permissions, best effort.

    Best effort because some filesystems (and Windows) do not implement POSIX
    modes. The call is still made everywhere so that on the platforms which do
    -- which is where engagement evidence actually lives -- the protection is
    present rather than aspirational. ``verify_permissions`` reports what was
    actually achieved, so a report never claims a restriction the filesystem
    refused.
    """
    try:
        os.chmod(path, FILE_MODE if os.path.isfile(path) else DIR_MODE)
        return True
    except (OSError, NotImplementedError):
        return False


def render_response(response):
    """Serialise a response into the length-declared envelope.

    ENGINEERING IMPROVEMENT (review finding: "separate response headers from
    response bodies"), applied to storage as well as to parsing.

    The previous format was::

        HTTP 200  (curl rc=0)
        <blank>
        <headers>
        <blank>
        <body>

    and it was read back by splitting on blank lines. A response body is
    target-controlled, so a body containing a blank line followed by forged
    header lines changed what ``reclassify`` believed the headers were -- which
    is the same defect as the transport one, reintroduced at the point where
    stored bytes are re-judged. Declaring the length of each section removes
    the ambiguity entirely: the body cannot lie about how long it is, because
    the length is written by the capturing process and covered by the
    evidence manifest's SHA-256.
    """
    headers = response.headers or ""
    body = response.body or ""
    meta = getattr(response, "meta", None) or {}
    head = ("%s status=%s curl_rc=%s header_chars=%d body_chars=%d "
            "truncated=%s"
            % (ENVELOPE_MAGIC, response.status, meta.get("curl_rc"),
               len(headers), len(body),
               "true" if meta.get("body_truncated") else "false"))
    return head + SECTION_SEP + headers + SECTION_SEP + body


def parse_response_file(path):
    """Read a stored response back. Returns a dict.

    Understands the length-declared envelope and, for evidence captured by an
    earlier version, falls back to the old blank-line split -- flagging the
    result ``legacy_format: True`` so a caller can say that those bytes were
    parsed heuristically rather than exactly.
    """
    # newline="" is essential, not stylistic. Header dumps carry CRLF, and
    # universal-newline translation would silently rewrite every "\r\n" to
    # "\n" on the way in -- shifting every character offset the envelope
    # declares, so the body slice would start inside the headers. The
    # framework's own live-versus-reclassified differential test is what
    # caught this; without that test the drift would have shown up as a
    # verdict that changed when a run was re-judged.
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        blob = fh.read()
    return parse_response_text(blob)


def parse_response_text(blob):
    if blob.startswith(ENVELOPE_MAGIC):
        head, _, rest = blob.partition("\n")
        fields = {}
        for token in head.split()[1:]:
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value
        try:
            n = int(fields.get("header_chars", 0))
            m = int(fields.get("body_chars", 0))
        except ValueError:
            n = m = 0
        # ``rest`` still carries the blank line that ends the envelope header.
        if rest.startswith("\n"):
            rest = rest[1:]
        headers = rest[:n]
        body = rest[n + len(SECTION_SEP):n + len(SECTION_SEP) + m]
        return {
            "status": fields.get("status", "000"),
            "curl_rc": fields.get("curl_rc"),
            "headers": headers,
            "body": body,
            "truncated": fields.get("truncated") == "true",
            "legacy_format": False,
        }

    # Legacy: "HTTP <status>  (curl rc=N)\n\n<headers>\n\n<body>"
    import re
    m0 = re.match(r"HTTP (\d{3}|000)", blob)
    status = m0.group(1) if m0 else "000"
    parts = re.split(r"\r?\n\r?\n", blob, maxsplit=2)
    return {
        "status": status,
        "curl_rc": None,
        "headers": parts[1] if len(parts) > 1 else "",
        "body": parts[2] if len(parts) > 2 else "",
        "truncated": False,
        "legacy_format": True,
    }


class EvidenceStore(object):
    def __init__(self, evidence_root, run_id=None, forbidden_roots=None,
                 metadata=None, retention_days=None):
        self.root = ensure_engagement_dir(evidence_root,
                                          forbidden_roots=forbidden_roots)
        self.run_id = safe_component(run_id or new_run_id(), what="run id")
        self.run_dir = safe_join(self.root, self.run_id, what="run directory")
        os.makedirs(self.run_dir, exist_ok=True)
        restrict(self.run_dir)
        self.results = []
        self.metadata = dict(metadata or {})
        self.metadata.setdefault("run_id", self.run_id)
        self.metadata.setdefault("started_utc", _utc_now())
        # ENGINEERING IMPROVEMENT (review finding: "protect captured
        # credentials and personal data"). Raw evidence is restricted and
        # carries a stated retention period, so "keep it until someone
        # remembers to delete it" is not the policy by default.
        self.retention_days = (retention_days if retention_days is not None
                               else DEFAULT_RETENTION_DAYS)
        self.metadata.setdefault("retention_days", self.retention_days)
        self.metadata.setdefault("retain_until", self.retain_until())
        self.metadata.setdefault(
            "handling",
            "RESTRICTED RAW EVIDENCE. Contains request and response bytes, "
            "and trace files that include credentials sent in headers. Do "
            "not share this directory. Produce a redacted copy for "
            "distribution (apiscan redact) and share that instead.")

    def retain_until(self):
        if not self.retention_days:
            return None
        started = datetime.datetime.now(datetime.timezone.utc)
        return (started + datetime.timedelta(days=self.retention_days)).date(
        ).isoformat()

    # -- paths -----------------------------------------------------------
    def path(self, case_id, kind):
        """Evidence path for one case, proven to stay inside the run directory.

        ENGINEERING IMPROVEMENT (review finding: "validate resolved file
        destinations before writing"). A case id reaches the filesystem by
        string interpolation, and case ids are not all framework-generated:
        ``--ids`` is operator input, an imported corpus JSON and a findings
        register are file input. An id of ``../../../etc/cron.d/x`` previously
        resolved wherever it pointed.
        """
        return safe_join(self.run_dir, "%s.%s.txt" % (
            safe_component(case_id, what="case id"), kind),
            what="evidence file")

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
        """Persist the response exactly as observed, in a length-declared
        envelope that its own content cannot reshape."""
        path = self.response_path(case_id)
        with open(path, "w", encoding="utf-8", errors="replace",
                  newline="") as fh:
            fh.write(render_response(response))
        restrict(path)
        return path

    def read_response(self, case_id):
        """Parse a stored response back into its sections."""
        return parse_response_file(self.response_path(case_id))

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
        unrestricted = []
        for name in sorted(os.listdir(self.run_dir)):
            full = os.path.join(self.run_dir, name)
            if not os.path.isfile(full) or name == "manifest.json":
                continue
            if not restrict(full):
                unrestricted.append(name)
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
            # Stated rather than assumed: a filesystem that cannot apply
            # POSIX modes must not leave the report implying it did.
            "access": {
                "mode_applied": "0600 files / 0700 directory"
                                if not unrestricted else "partial",
                "files_not_restricted": unrestricted,
                "retention_days": self.retention_days,
                "retain_until": self.metadata.get("retain_until"),
            },
        }
        mpath = os.path.join(self.run_dir, "manifest.json")
        with open(mpath, "w") as fh:
            json.dump(manifest, fh, indent=2)
        restrict(mpath)

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
        full = safe_join(run_dir, safe_component(
            filename, what="derived artifact name"),
            what="derived artifact")
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
        restrict(full)
        restrict(mpath)
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


def run_kind(run_dir):
    """The ``kind`` a run recorded for itself: "corpus", "transport-posture"...

    Unknown rather than assumed when there is no metadata, because guessing is
    how a transport-posture run ends up reported as an assessment.
    """
    meta_path = os.path.join(run_dir, "run.json")
    if not os.path.isfile(meta_path):
        return None
    try:
        with open(meta_path) as fh:
            return json.load(fh).get("kind")
    except (ValueError, OSError):
        return None


def list_runs(evidence_root, kind=None):
    """Run directories under *evidence_root*, newest last, optionally filtered.

    Run ids are timestamps, so lexical order is chronological order.
    """
    try:
        names = sorted(d for d in os.listdir(evidence_root)
                       if os.path.isdir(os.path.join(evidence_root, d))
                       and d[:1].isdigit())
    except OSError:
        return []
    runs = [os.path.join(evidence_root, n) for n in names]
    if kind is None:
        return runs
    return [r for r in runs if run_kind(r) == kind]


def find_latest_run(evidence_root, kind=None):
    """The most recent run, optionally of a given kind.

    ENGINEERING IMPROVEMENT (review finding: "use explicit run IDs for reports
    so a later TLS check cannot accidentally replace the intended scan
    results"). ``report`` and ``capture`` used to take whatever ran last. A
    ``tls-posture`` run is two transport observations and is very often the
    last thing an assessor does, so the deliverable was silently built from it
    -- a report with a clean-looking tally about nothing. Asking for a *kind*
    makes that mistake impossible to make by omission; the CLI additionally
    requires the run to be named or the choice to be stated.
    """
    if kind is not None:
        runs = list_runs(evidence_root, kind=kind)
        return runs[-1] if runs else None

    pointer = os.path.join(evidence_root, "latest-run.txt")
    if os.path.exists(pointer):
        with open(pointer) as fh:
            candidate = fh.read().strip()
        if candidate and os.path.isdir(candidate):
            return candidate
    runs = list_runs(evidence_root)
    return runs[-1] if runs else None
