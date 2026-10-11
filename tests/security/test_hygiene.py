"""Framework hygiene tests.

These assert properties of the framework ITSELF rather than of a target.

A deliberate boundary: this suite checks only generic, client-independent
properties -- no real hostnames, no credential-shaped literals, synthetic-only
fixtures, no writes into the framework tree. It does NOT check for a specific
client's identifiers, and must not: embedding a client-identifier list in the
framework would ship the very data the framework exists to keep out. That check
lives in the separate, confidential validator held in the audit workspace.
"""
import os
import re
import unittest

from tests.support import ROOT  # noqa: F401
from framework.core.pathguard import FRAMEWORK_ROOT

TEXT_EXTENSIONS = {".py", ".json", ".md", ".txt", ".sh", ".cfg", ".toml", ".yml"}
SKIP_DIRS = {".venv", "__pycache__", ".git", "evidence", "reports", "poc",
             "findings", ".snapshots"}

#: Hostnames a releasable framework may legitimately contain.
ALLOWED_HOSTS = {
    "example.com", "example.net", "example.org",      # RFC 2606
    "attacker.example.net", "api.example.com",
    "proxy-control",                                  # placeholder control host
    "localhost",
}

#: RFC 2606 also reserves ".example" as a top-level domain, so any host ending
#: in it is reserved regardless of the label in front.
ALLOWED_TLDS = (".example", ".invalid", ".test", ".localhost")

#: Documentation / loopback ranges only (RFC 5737, RFC 1122, RFC 3927).
ALLOWED_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "169.254.169.254",                                # in a DETECTOR rule
}
ALLOWED_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "10.", "172.16.",
                       "192.168.")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"https?://([A-Za-z0-9.-]+)")

SECRET_SHAPES = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PEM private key"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"(?:ey[A-Za-z0-9_-]{10,}\.){2}[A-Za-z0-9_-]{10,}"), "JWT"),
)

#: Files that legitimately contain secret-shaped example strings, because
#: detecting those shapes is their purpose.
SHAPE_EXEMPT = {
    os.path.join("framework", "oracle", "rules", "disclosure.json"),
    os.path.join("framework", "core", "profile.py"),
    os.path.join("tests", "unit", "test_profile.py"),
    os.path.join("tests", "unit", "test_detectors.py"),
    os.path.join("tests", "security", "test_hygiene.py"),
    # Its gates are exercised with deliberately secret-shaped NEGATIVE
    # fixtures; detecting those shapes is the point of the file.
    os.path.join("tests", "unit", "test_maintenance.py"),
}


def framework_files():
    for dirpath, dirnames, filenames in os.walk(FRAMEWORK_ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in TEXT_EXTENSIONS:
                full = os.path.join(dirpath, name)
                yield os.path.relpath(full, FRAMEWORK_ROOT), full


def read(path):
    with open(path, "r", errors="replace") as fh:
        return fh.read()


class TestNoSecrets(unittest.TestCase):
    def test_no_credential_shaped_literals(self):
        offenders = []
        for rel, full in framework_files():
            if rel in SHAPE_EXEMPT:
                continue
            text = read(full)
            for rx, label in SECRET_SHAPES:
                if rx.search(text):
                    offenders.append("%s: %s" % (rel, label))
        self.assertEqual(offenders, [], offenders)

    def test_no_env_or_key_files_are_committed(self):
        bad = []
        for dirpath, dirnames, filenames in os.walk(FRAMEWORK_ROOT):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.startswith(".env") or name.endswith(
                        (".p12", ".pfx", ".key", ".pem", ".crt", ".der",
                         ".jks")):
                    bad.append(os.path.relpath(os.path.join(dirpath, name),
                                               FRAMEWORK_ROOT))
        self.assertEqual(bad, [], bad)

    def test_gitignore_covers_engagement_artifacts(self):
        with open(os.path.join(FRAMEWORK_ROOT, ".gitignore")) as fh:
            text = fh.read()
        for pattern in (".env", "evidence/", "reports/", "*.p12", "*.key",
                        ".DS_Store", "*.png", "*.xlsx"):
            self.assertIn(pattern, text, pattern)


class TestSyntheticOnly(unittest.TestCase):
    def test_only_reserved_hostnames_appear(self):
        offenders = []
        for rel, full in framework_files():
            for host in HOST_RE.findall(read(full)):
                bare = host.split(":")[0]
                if bare in ALLOWED_HOSTS or bare in ALLOWED_IPS:
                    continue
                if any(bare.endswith("." + d) or bare == d
                       for d in ALLOWED_HOSTS):
                    continue
                if bare.endswith(ALLOWED_TLDS):
                    continue
                if IP_RE.fullmatch(bare):
                    continue
                offenders.append("%s: %s" % (rel, bare))
        self.assertEqual(sorted(set(offenders)), [],
                         "non-reserved hostname in the framework: %s"
                         % sorted(set(offenders)))

    def test_only_documentation_or_loopback_addresses_appear(self):
        offenders = []
        for rel, full in framework_files():
            for ip in IP_RE.findall(read(full)):
                if ip in ALLOWED_IPS:
                    continue
                if any(ip.startswith(p) for p in ALLOWED_IP_PREFIXES):
                    continue
                # Dotted version strings and OIDs are not addresses.
                if re.match(r"^\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,3}$", ip) and \
                        int(ip.split(".")[0]) < 10:
                    continue
                offenders.append("%s: %s" % (rel, ip))
        self.assertEqual(sorted(set(offenders)), [],
                         "non-documentation IP address: %s"
                         % sorted(set(offenders)))

    def test_example_profile_contains_no_literal_credentials(self):
        from framework.core import profile as P
        import json
        path = os.path.join(FRAMEWORK_ROOT, "configs", "examples",
                            "example-callback-api.json")
        with open(path) as fh:
            data = json.load(fh)
        self.assertEqual(P.scan_for_literal_secrets(data), [])

    def test_every_identifier_in_the_example_profile_is_marked_synthetic(self):
        import json
        path = os.path.join(FRAMEWORK_ROOT, "configs", "examples",
                            "example-callback-api.json")
        with open(path) as fh:
            data = json.load(fh)
        for name, space in (data.get("identifier_spaces") or {}).items():
            example = space.get("example", "")
            self.assertTrue(example, name)
            # Either an explicit SYNTH- prefix, or a placeholder built almost
            # entirely from zeros (a nil-style UUID keeps the structural
            # version/variant digits, so allow a couple of distinct others).
            filler = set(example) - set("0-")
            self.assertTrue(
                example.startswith("SYNTH") or len(filler) <= 2,
                "identifier space %r example %r is not obviously synthetic"
                % (name, example))


class TestRuntimeIsolation(unittest.TestCase):
    def test_framework_writes_nothing_into_its_own_tree(self):
        """Engagement output inside the framework is the likeliest route for
        client data into a shared repository."""
        from framework.core.errors import PathGuardError
        from framework.evidence.store import EvidenceStore
        for sub in ("evidence", "out", "reports"):
            with self.assertRaises(PathGuardError):
                EvidenceStore(os.path.join(FRAMEWORK_ROOT, sub))

    def test_no_module_holds_a_target_constant(self):
        """A base URL baked into code would couple the framework to one target."""
        offenders = []
        for rel, full in framework_files():
            if not rel.endswith(".py") or rel.startswith("tests"):
                continue
            for line in read(full).splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or '"""' in stripped:
                    continue
                m = re.search(r'^\s*(?:BASE|BASE_URL|TARGET|HOST)\s*=\s*["\']'
                              r'https?://', line)
                if m:
                    offenders.append("%s: %s" % (rel, stripped[:70]))
        self.assertEqual(offenders, [], offenders)

    def test_scope_default_is_deny_for_dangerous_classes(self):
        from framework.governance.scope import DEFAULT_DENY, ScopePolicy
        policy = ScopePolicy.default()
        for klass in ("state_mutating", "volumetric", "destructive",
                      "infrastructure_pivot", "bulk_extraction"):
            self.assertIn(klass, DEFAULT_DENY)
            self.assertIn(klass, policy.deny_classes)

    def test_rate_limit_module_refuses_without_authorisation(self):
        from framework.core.errors import ScopeViolation
        from framework.modules import rate_limit
        with self.assertRaises(ScopeViolation):
            rate_limit.probe(None, None, None, authorised=False)

    def test_rate_limit_ceilings_cannot_be_exceeded(self):
        from framework.core.errors import ScopeViolation
        from framework.modules import rate_limit
        with self.assertRaises(ScopeViolation):
            rate_limit.probe(None, None, None, requests=100000, workers=500,
                             authorised=True)

    def test_window_capture_offers_no_full_screen_path(self):
        """An early version of the source tool captured the whole screen and
        pulled an unrelated window into a deliverable. That path must not
        exist."""
        from tools.capture import window
        source = read(os.path.join(FRAMEWORK_ROOT, "tools", "capture",
                                   "window.py"))
        self.assertNotIn("screencapture -x -t png\"", source)
        for forbidden in ("'-R'", '"-R"', "screencapture_full",
                          "capture_screen"):
            self.assertNotIn(forbidden, source)
        self.assertIn("-l", source)
        self.assertTrue(hasattr(window, "select_main_window"))


if __name__ == "__main__":
    unittest.main()
