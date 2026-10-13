"""CLI integration: the operator-facing surface.

Exercises the real command path against a loopback mock, including the two
properties that matter most: commands that claim to send nothing really send
nothing, and `init-engagement` refuses to scaffold inside the framework.
"""
import json
import os
import shutil
import tempfile
import unittest

from tests.fixtures.mock_service import MockService
from tests.support import ROOT, TEST_ENV  # noqa: F401
from automation.cli.main import main
from framework.core.pathguard import FRAMEWORK_ROOT


class CLIBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="apiscan-cli-")
        cls.eng = os.path.join(cls.tmp, "engagement")
        cls.service = MockService(strict=False)
        cls.service.__enter__()
        cls._saved_env = {k: os.environ.get(k) for k in TEST_ENV}
        os.environ.update(TEST_ENV)

        cls.assertEqual_ = unittest.TestCase.assertEqual
        rc = main(["init-engagement", cls.eng, "--name", "mock-target",
                   "--reference", "TEST-0001"])
        assert rc == 0

        cls.profile_path = os.path.join(cls.eng, "profile.json")
        with open(cls.profile_path) as fh:
            profile = json.load(fh)
        profile["transport"]["base_url"] = cls.service.base_url
        profile["transport"]["proxy"] = None
        with open(cls.profile_path, "w") as fh:
            json.dump(profile, fh, indent=2)

        cls.scope_path = os.path.join(cls.eng, "scope-policy.json")
        with open(cls.scope_path) as fh:
            scope = json.load(fh)
        # Keep the pristine scaffold: the setup below authorises
        # state-mutating cases so the scan can run, which would otherwise make
        # the default-deny assertion read its own modification.
        cls.scaffolded_scope = json.loads(json.dumps(scope))
        scope["deny_classes"] = ["volumetric", "destructive"]
        scope["authorisations"] = [{
            "classes": ["state_mutating"], "authorised_by": "Test",
            "authorised_on": "2026-10-06", "reference": "SELFTEST"}]
        with open(cls.scope_path, "w") as fh:
            json.dump(scope, fh, indent=2)

        cls.evidence = os.path.join(cls.eng, "evidence")

    @classmethod
    def tearDownClass(cls):
        cls.service.__exit__(None, None, None)
        for key, value in cls._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(cls.tmp, ignore_errors=True)


class TestScaffolding(CLIBase):
    def test_engagement_files_exist_with_safe_permissions(self):
        for name in ("profile.json", "scope-policy.json", ".env",
                     ".gitignore"):
            self.assertTrue(os.path.exists(os.path.join(self.eng, name)), name)
        mode = os.stat(os.path.join(self.eng, ".env")).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_scaffolded_scope_is_default_deny(self):
        scope = self.scaffolded_scope
        self.assertEqual(scope["authorisations"], [],
                         "a freshly scaffolded engagement must authorise "
                         "nothing")
        from framework.governance.scope import DEFAULT_DENY
        for klass in DEFAULT_DENY:
            self.assertIn(klass, scope["deny_classes"],
                          "the scaffold must deny every class the framework "
                          "considers default-denied, including the payload "
                          "classes that can damage a vulnerable target")

    def test_refuses_to_scaffold_inside_the_framework(self):
        """The CLI converts a FrameworkError into exit code 2 rather than a
        traceback, so assert the contract the operator sees."""
        target = os.path.join(FRAMEWORK_ROOT, "engagements", "nope")
        self.assertEqual(main(["init-engagement", target]), 2)
        self.assertFalse(os.path.exists(target))
        self.assertFalse(os.path.exists(os.path.join(FRAMEWORK_ROOT,
                                                     "engagements")))


class TestNonSendingCommands(CLIBase):
    def requests_made(self):
        from tests.fixtures.mock_service import STATE
        return STATE.requests

    def test_validate_sends_nothing(self):
        before = self.requests_made()
        self.assertEqual(main(["validate", "--profile", self.profile_path,
                               "--scope", self.scope_path]), 0)
        self.assertEqual(self.requests_made(), before)

    def test_generate_sends_nothing(self):
        before = self.requests_made()
        out = os.path.join(self.tmp, "corpus.json")
        self.assertEqual(main(["generate", "--profile", self.profile_path,
                               "--scope", self.scope_path, "--out", out]), 0)
        self.assertEqual(self.requests_made(), before)
        with open(out) as fh:
            self.assertGreater(len(json.load(fh)), 100)

    def test_preflight_offline_sends_nothing(self):
        before = self.requests_made()
        main(["preflight", "--profile", self.profile_path, "--offline",
              "--all", "--json"])
        self.assertEqual(self.requests_made(), before)

    def test_validate_rejects_a_bad_profile(self):
        broken = os.path.join(self.tmp, "broken.json")
        with open(broken, "w") as fh:
            json.dump({"schema": "target-profile/1"}, fh)
        self.assertEqual(main(["validate", "--profile", broken]), 2)


class TestFullWorkflow(CLIBase):
    def test_scan_report_capture_reclassify(self):
        # --mode active: this test exercises the whole pipeline, which is
        # what an authorised assessment does. The cautious default mode is
        # covered by its own tests in tests/regression.
        rc = main(["scan", "--profile", self.profile_path, "--scope",
                   self.scope_path, "--evidence", self.evidence,
                   "--phases", "P1,P2", "--families", "A,B", "--quiet",
                   "--mode", "active", "--yes",
                   "--note", "cli integration test"])
        self.assertEqual(rc, 0)

        runs = [d for d in os.listdir(self.evidence)
                if os.path.isdir(os.path.join(self.evidence, d))]
        self.assertEqual(len(runs), 1)
        run_dir = os.path.join(self.evidence, runs[0])
        for name in ("results.json", "run.json", "manifest.json"):
            self.assertTrue(os.path.exists(os.path.join(run_dir, name)), name)

        from framework.evidence.store import EvidenceStore
        self.assertEqual(EvidenceStore.verify(run_dir), [])

        # reclassify must not send anything
        from tests.fixtures.mock_service import STATE
        before = STATE.requests
        self.assertEqual(main(["reclassify", "--profile", self.profile_path,
                               "--evidence", self.evidence, "--latest"]), 0)
        self.assertEqual(STATE.requests, before)

        # report: without --not-established it is NOT issuable (exit 1)
        reports = os.path.join(self.eng, "reports")
        rc = main(["report", "--evidence", self.evidence, "--out", reports,
                   "--promote", "--no-xlsx", "--latest"])
        self.assertEqual(rc, 1, "a report with no limitations must not be "
                                "reported as issuable")

        limits = os.path.join(self.eng, "limits.txt")
        with open(limits, "w") as fh:
            fh.write("TLS was not assessed.\nRate limiting was out of scope.\n")
        rc = main(["report", "--evidence", self.evidence, "--out", reports,
                   "--promote", "--no-xlsx", "--latest",
                   "--not-established", limits,
                   "--scope-note", "Loopback mock only.",
                   "--engagement", "TEST-0001"])
        self.assertEqual(rc, 0)
        with open(os.path.join(reports, "report.md")) as fh:
            text = fh.read()
        self.assertIn("TLS was not assessed", text)
        self.assertIn("Coverage limitations", text)

        # capture renders from stored bytes only
        poc = os.path.join(self.eng, "poc")
        before = STATE.requests
        with open(os.path.join(run_dir, "results.json")) as fh:
            first_case = json.load(fh)[0]
        self.assertEqual(main(["capture", "--evidence", self.evidence,
                               "--out", poc, "--latest", "--ids",
                               first_case["case_id"]]), 0)
        self.assertEqual(STATE.requests, before)
        self.assertTrue(any(f.endswith(".html") for f in os.listdir(poc)))

    def test_evidence_root_inside_the_framework_is_refused(self):
        rc = main(["scan", "--profile", self.profile_path, "--scope",
                   self.scope_path, "--evidence",
                   os.path.join(FRAMEWORK_ROOT, "evidence"), "--quiet",
                   "--mode", "active", "--yes"])
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(os.path.join(FRAMEWORK_ROOT,
                                                     "evidence")))


if __name__ == "__main__":
    unittest.main()


class TestOfflineCommandsNeedNoCredentials(CLIBase):
    """D2. ``reclassify`` is documented as sending nothing, yet it refused to
    start without every ${ENV:...} reference resolved. It re-judges stored
    bytes and never authenticates to anything, so demanding live credentials
    to read a finished run is friction with no safety value -- and it bites
    exactly when an engagement is over and the secrets have been cleared."""

    @classmethod
    def setUpClass(cls):
        super(TestOfflineCommandsNeedNoCredentials, cls).setUpClass()
        rc = main(["scan", "--profile", cls.profile_path,
                   "--scope", cls.scope_path, "--evidence", cls.evidence,
                   "--phases", "P1", "--direct", "--quiet",
                   "--mode", "active", "--yes"])
        assert rc == 0, rc

    def _without_credentials(self, argv):
        saved = {k: os.environ.pop(k) for k in list(TEST_ENV) if k in os.environ}
        try:
            return main(argv)
        finally:
            os.environ.update(saved)

    def test_reclassify_runs_with_no_credentials_in_the_environment(self):
        rc = self._without_credentials(
            ["reclassify", "--profile", self.profile_path,
             "--evidence", self.evidence, "--latest"])
        self.assertEqual(rc, 0, "reclassify must not require live credentials")

    def test_reclassify_still_sends_nothing(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._without_credentials(
                ["reclassify", "--profile", self.profile_path,
                 "--evidence", self.evidence, "--latest"])
        self.assertIn("No request was sent.", buf.getvalue())

    def test_scanning_without_credentials_is_still_refused(self):
        """The relaxation must not leak into the command that sends traffic."""
        rc = self._without_credentials(
            ["scan", "--profile", self.profile_path, "--scope",
             self.scope_path, "--evidence", self.evidence, "--phases", "P1",
             "--direct", "--quiet", "--mode", "active", "--yes"])
        self.assertNotEqual(rc, 0,
                            "scan must still demand resolved credentials")


class TestTlsPostureCommand(CLIBase):
    """The transport-posture module had no CLI surface, so the only way to run
    it was by hand in Python -- which is also how it ended up outside the scope
    gate. A subcommand gives it one entry point, and that entry point gates."""

    def _profile_at(self, base_url):
        """A profile pointing at a closed loopback port: probes refuse
        instantly and nothing leaves the host."""
        path = os.path.join(self.tmp, "tls-profile.json")
        with open(self.profile_path) as fh:
            prof = json.load(fh)
        prof["transport"]["base_url"] = base_url
        with open(path, "w") as fh:
            json.dump(prof, fh, indent=2)
        return path

    def _scope(self, name, spec):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as fh:
            json.dump(spec, fh, indent=2)
        return path

    def test_it_runs_and_writes_direct_stamped_evidence(self):
        out = os.path.join(self.tmp, "tls-evidence")
        scope = self._scope("allow-probe.json", {
            "schema": "scope-policy/1",
            "deny_classes": ["state_mutating", "volumetric"],
            "authorisations": [{
                "classes": ["transport_probe", "direct_transport"],
                "authorised_by": "Test", "authorised_on": "2026-10-06",
                "reference": "SELFTEST"}]})
        rc = main(["tls-posture",
                   "--profile", self._profile_at("https://127.0.0.1:1/v1"),
                   "--scope", scope, "--evidence", out, "--quiet"])
        self.assertEqual(rc, 0)
        runs = [d for d in os.listdir(out)
                if os.path.isdir(os.path.join(out, d))]
        self.assertEqual(len(runs), 1)
        run_dir = os.path.join(out, runs[0])
        with open(os.path.join(run_dir, "run.json")) as fh:
            meta = json.load(fh)
        self.assertEqual(meta["capture_method"], "direct")
        self.assertEqual(meta["kind"], "transport-posture")
        from framework.evidence.store import EvidenceStore
        self.assertEqual(EvidenceStore.verify(run_dir), [])

    def test_a_policy_denying_transport_probes_stops_it(self):
        scope = self._scope("deny-probe.json", {
            "schema": "scope-policy/1",
            "deny_classes": ["transport_probe"]})
        out = os.path.join(self.tmp, "tls-denied")
        rc = main(["tls-posture",
                   "--profile", self._profile_at("https://127.0.0.1:1/v1"),
                   "--scope", scope, "--evidence", out, "--quiet"])
        self.assertNotEqual(rc, 0, "a denied probe must not succeed")

    def test_require_proxy_without_a_direct_authorisation_stops_it(self):
        scope = self._scope("require-proxy.json", {
            "schema": "scope-policy/1", "deny_classes": [],
            "require_proxy": True})
        out = os.path.join(self.tmp, "tls-proxy-required")
        rc = main(["tls-posture",
                   "--profile", self._profile_at("https://127.0.0.1:1/v1"),
                   "--scope", scope, "--evidence", out, "--quiet"])
        self.assertNotEqual(rc, 0)
