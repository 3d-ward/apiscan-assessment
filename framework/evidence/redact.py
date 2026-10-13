"""Redacted copies of evidence, for anything that leaves the engagement.

ENGINEERING IMPROVEMENT (review finding: "protect captured credentials and
personal data -- shared reports are redacted; raw evidence has restricted
access and a defined retention period"), implemented the way that finding
asks for it:

    For evidence, preserve restricted raw originals when necessary and
    produce separate redacted copies. Redacting the only original could
    undermine later verification.

So this module never writes into a run directory. It reads a run and produces
a parallel, redacted tree somewhere else, with its own manifest recording both
hashes -- the original's and the copy's -- so a reader can confirm which raw
artifact a redacted one came from without being given the raw artifact.

What gets redacted, and why that list:

  * the resolved values of every ``${ENV:...}`` reference the profile uses.
    These are the actual credentials, and they appear verbatim in request
    headers inside ``--trace-ascii`` output. This is the single most important
    entry: a trace file is a credential leak in a text file.
  * the values of credential-bearing headers, by name, wherever they appear in
    a header dump or a trace -- so a credential rotated since capture, or one
    supplied outside the profile, is still caught.
  * credential SHAPES: JWTs, PEM private keys, AWS keys, GitHub and Slack
    tokens, and Basic/Bearer values. These catch what the first two miss,
    including a credential the target returned in a response.
  * optionally, personal data: e-mail addresses, long digit runs that look
    like account or card numbers, and any body path the profile declares.
    Optional because over-redaction destroys the evidential value of a
    finding, and the operator is the one who knows which fields matter.

Redaction is deliberately NOT reversible and NOT a hash: a consistent token
per distinct secret would let a reader confirm a guessed value. Each distinct
secret gets a stable label (``[REDACTED:credential:1]``) so a reader can still
see that two occurrences were the same value without learning it.
"""
import json
import os
import re
import shutil

from ..core.pathguard import ensure_engagement_dir, safe_relative_join
from .store import restrict, sha256_file

#: Header names whose VALUE is a credential. Matched case-insensitively in
#: header dumps and in trace output.
CREDENTIAL_HEADERS = (
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "apikey", "api-key", "x-auth-token", "x-access-token",
    "x-session-token", "x-csrf-token", "x-amz-security-token",
)

#: Shapes that are credentials wherever they appear.
CREDENTIAL_SHAPES = (
    ("pem-private-key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*"
                r"PRIVATE KEY-----", re.S)),
    ("jwt", re.compile(r"\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
                       r"\.[A-Za-z0-9_-]{8,}\b")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{12,})")),
    ("basic-credential", re.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/=]{12,})")),
)

#: Personal data shapes. Applied only when the caller asks for them.
PII_SHAPES = (
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[A-Za-z]{2,}\b")),
    ("long-digit-run", re.compile(r"\b\d{11,19}\b")),
)

#: Files copied verbatim: they are structured records the framework wrote, not
#: captured traffic, and rewriting them would break the schemas that read them.
#: They are still scanned, and a hit in one is reported as a problem rather
#: than silently edited, because a credential in results.json is a defect in
#: this framework and must be fixed at the source.
STRUCTURAL_FILES = ("manifest.json",)

BINARY_SUFFIXES = (".png", ".jpg", ".jpeg", ".pdf", ".xlsx", ".p12", ".pfx",
                   ".der", ".gz", ".zip")

#: A value this module has already replaced. Matching it again would relabel a
#: label, which costs nothing in safety but makes the output misleading: two
#: labels for one secret reads as two secrets.
ALREADY_REDACTED = re.compile(r"^\[REDACTED:[a-z-]+:\d+\]$")


class Redactor(object):
    """Applies a redaction policy to text, counting what it replaced."""

    def __init__(self, secrets=None, header_names=None, include_pii=False,
                 extra_patterns=None):
        #: Literal values to remove. Longest first, so a secret that contains
        #: another is replaced whole rather than leaving a fragment.
        self.secrets = sorted({s for s in (secrets or []) if s and len(s) >= 4},
                              key=len, reverse=True)
        self.header_names = tuple(
            n.lower() for n in (header_names or CREDENTIAL_HEADERS))
        self.include_pii = bool(include_pii)
        self.extra_patterns = list(extra_patterns or [])
        self._labels = {}
        self._next = {}

    # -- labelling -------------------------------------------------------
    def label(self, kind, value):
        """A stable, non-reversible label for one distinct secret value.

        Stable within a redaction run so a reader can see that two
        occurrences were the same value. Not derived from the value, so the
        label cannot be used to confirm a guess.
        """
        key = (kind, value)
        if key not in self._labels:
            self._next[kind] = self._next.get(kind, 0) + 1
            self._labels[key] = "[REDACTED:%s:%d]" % (kind, self._next[kind])
        return self._labels[key]

    # -- application -----------------------------------------------------
    def apply(self, text):
        """Return (redacted_text, {kind: count})."""
        if not text:
            return text, {}
        hits = {}

        def bump(kind, n=1):
            hits[kind] = hits.get(kind, 0) + n

        for secret in self.secrets:
            if secret in text:
                bump("credential", text.count(secret))
                text = text.replace(secret, self.label("credential", secret))

        # Header values, by name, in both "Name: value" dumps and trace lines
        # (curl's trace prefixes each line, so the name may not start the line).
        for name in self.header_names:
            pattern = re.compile(r"(?i)(%s\s*:\s*)([^\r\n]+)"
                                 % re.escape(name))

            def repl(match):
                value = match.group(2).strip()
                if ALREADY_REDACTED.match(value):
                    return match.group(0)
                bump("credential")
                return match.group(1) + self.label("credential", value)
            text = pattern.sub(repl, text)

        for kind, pattern in CREDENTIAL_SHAPES:
            def repl_shape(match, kind=kind):
                # Group 1 where the pattern isolates the secret from its
                # scheme word, otherwise the whole match.
                value = match.group(1) if match.groups() else match.group(0)
                if ALREADY_REDACTED.match(value.strip()):
                    return match.group(0)
                bump(kind)
                replacement = self.label(kind, value)
                if match.groups():
                    return match.group(0).replace(value, replacement)
                return replacement
            text = pattern.sub(repl_shape, text)

        if self.include_pii:
            for kind, pattern in PII_SHAPES:
                def repl_pii(match, kind=kind):
                    bump(kind)
                    return self.label(kind, match.group(0))
                text = pattern.sub(repl_pii, text)

        for kind, pattern in self.extra_patterns:
            compiled = (pattern if hasattr(pattern, "sub")
                        else re.compile(pattern))

            def repl_extra(match, kind=kind):
                bump(kind)
                return self.label(kind, match.group(0))
            text = compiled.sub(repl_extra, text)

        return text, hits

    def describe(self):
        return {
            "literal_secret_values": len(self.secrets),
            "credential_headers": list(self.header_names),
            "credential_shapes": [k for k, _ in CREDENTIAL_SHAPES],
            "personal_data_shapes": ([k for k, _ in PII_SHAPES]
                                     if self.include_pii else []),
            "extra_patterns": [k for k, _ in self.extra_patterns],
            "reversible": False,
        }


def from_profile(profile, include_pii=False, extra_secrets=None):
    """Build a redactor that knows this engagement's actual credentials.

    The values come from the process environment, which is where the profile's
    ``${ENV:...}`` references resolve from. If the environment has since been
    cleared -- which is the right thing to do after an engagement -- the
    literal-value pass finds nothing and only the shape and header passes
    apply. That is reported rather than assumed, because a redaction that
    silently did less than it claimed is worse than one that refused.
    """
    secrets = list(extra_secrets or [])
    names = list(getattr(profile, "resolved_env", []) or [])
    for name in names:
        value = os.environ.get(name)
        if value:
            secrets.append(value)
    declared = (getattr(profile, "data", {}) or {}).get("redaction") or {}
    for name in declared.get("extra_env") or []:
        value = os.environ.get(name)
        if value:
            secrets.append(value)
    extra = [(p.get("label", "declared"), re.compile(p["pattern"]))
             for p in (declared.get("patterns") or []) if p.get("pattern")]
    headers = declared.get("header_names") or None
    return Redactor(
        secrets=secrets,
        header_names=([h.lower() for h in headers] + list(CREDENTIAL_HEADERS)
                      if headers else None),
        include_pii=include_pii or bool(declared.get("include_pii")),
        extra_patterns=extra), {
        "env_references_in_profile": names,
        "env_values_available": sum(1 for n in names if os.environ.get(n)),
        "note": ("literal credential values are only removable while they are "
                 "present in the environment; shape- and header-based "
                 "redaction applies either way"),
    }


def _is_binary(name):
    return name.lower().endswith(BINARY_SUFFIXES)


def redact_run(run_dir, out_dir, redactor, forbidden_roots=None,
               provenance=None):
    """Write a redacted copy of one run. The original is never modified.

    Returns the redaction manifest. Every file is accounted for: redacted,
    copied verbatim, or skipped as binary -- so a reader can tell that nothing
    was quietly dropped.
    """
    run_dir = os.path.abspath(run_dir)
    out_dir = ensure_engagement_dir(out_dir, forbidden_roots=forbidden_roots)
    restrict(out_dir)

    files = []
    problems = []
    for name in sorted(os.listdir(run_dir)):
        source = os.path.join(run_dir, name)
        if not os.path.isfile(source):
            continue
        dest = safe_relative_join(out_dir, name, what="redacted artifact")
        entry = {"file": name, "sha256_original": sha256_file(source)}

        if _is_binary(name):
            shutil.copy2(source, dest)
            restrict(dest)
            entry.update(disposition="copied-verbatim-binary",
                         redactions={},
                         note="binary artifact; not scanned. Review it by "
                              "hand before sharing.")
        else:
            with open(source, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            redacted, hits = redactor.apply(text)
            if name in STRUCTURAL_FILES:
                # Copy verbatim, but report any hit loudly: a credential in a
                # framework-written structural file is a defect here, not
                # something to paper over in a copy.
                shutil.copy2(source, dest)
                entry.update(disposition="copied-verbatim-structural",
                             redactions=hits)
                if hits:
                    problems.append(
                        "%s is a structural file written by the framework and "
                        "it matched %s. It was copied verbatim rather than "
                        "edited. Treat this as a defect to fix at the source."
                        % (name, ", ".join(sorted(hits))))
            else:
                with open(dest, "w", encoding="utf-8") as fh:
                    fh.write(redacted)
                entry.update(disposition="redacted", redactions=hits)
            restrict(dest)
        entry["sha256_redacted"] = sha256_file(dest)
        files.append(entry)

    total = {}
    for entry in files:
        for kind, count in (entry.get("redactions") or {}).items():
            total[kind] = total.get(kind, 0) + count

    manifest = {
        "schema": "redaction-manifest/1",
        "source_run": os.path.basename(run_dir),
        "source_run_path_note": ("the raw run is retained, unmodified and "
                                 "access-restricted, in the engagement "
                                 "directory; its path is deliberately not "
                                 "recorded here"),
        "generated_utc": _utc(),
        "policy": redactor.describe(),
        "provenance": dict(provenance or {}),
        "artifact_count": len(files),
        "artifacts": files,
        "redaction_totals": total,
        "problems": problems,
        "statement": (
            "This is a REDACTED COPY produced for distribution. Credential "
            "material and, where enabled, personal data have been replaced "
            "with stable non-reversible labels. The raw originals are "
            "unmodified and retained under restricted access, so the "
            "evidence manifest of the source run still verifies; each "
            "artifact below records the SHA-256 of both the original and "
            "this copy."),
    }
    mpath = os.path.join(out_dir, "redaction-manifest.json")
    with open(mpath, "w") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    restrict(mpath)
    return manifest


def _utc():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def scan_for_secrets(text, redactor):
    """Report what a redactor WOULD remove, without producing a copy.

    Used by the report renderers to refuse to embed an unredacted excerpt, and
    by tests to assert that a deliverable carries no credential material.
    """
    _, hits = redactor.apply(text)
    return hits
