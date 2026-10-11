import unittest

from tests.support import ROOT  # noqa: F401
from framework.core.errors import AuthorisationError
from framework.governance.scope import ScopePolicy


class FakeCase(object):
    def __init__(self, cid="X", endpoint="create", method="POST",
                 state_mutating=True, volume_class="single",
                 payload_class="benign", risk_classes=None, use_proxy=None):
        self.id = cid
        self.endpoint = endpoint
        self.method = method
        self.state_mutating = state_mutating
        self.volume_class = volume_class
        self.payload_class = payload_class
        self.risk_classes = risk_classes or []
        self.use_proxy = use_proxy


class TestScopeDefaults(unittest.TestCase):
    """The source hand-listed excluded case IDs in a separate file, so a newly
    added mutating case was not excluded and went out unreviewed. Matching on
    attributes closes that gap: the dangerous default is now denial."""

    def setUp(self):
        self.policy = ScopePolicy.default()

    def test_a_new_unflagged_mutating_case_is_denied(self):
        permitted, reason = self.policy.evaluate(FakeCase("BRAND-NEW"))
        self.assertFalse(permitted)
        self.assertIn("state_mutating", reason)

    def test_read_only_is_permitted(self):
        self.assertTrue(self.policy.permits(FakeCase(state_mutating=False)))

    def test_volumetric_is_denied(self):
        self.assertFalse(self.policy.permits(
            FakeCase(state_mutating=False, volume_class="burst")))

    def test_explicit_risk_classes_are_honoured(self):
        self.assertFalse(self.policy.permits(
            FakeCase(state_mutating=False, risk_classes=["destructive"])))

    def test_require_raises_with_actionable_guidance(self):
        with self.assertRaises(AuthorisationError) as ctx:
            self.policy.require(FakeCase())
        self.assertIn("authorised_by", str(ctx.exception))


class TestAuthorisations(unittest.TestCase):
    def policy(self, **extra):
        spec = {"schema": "scope-policy/1",
                "deny_classes": ["state_mutating", "volumetric"]}
        spec.update(extra)
        return ScopePolicy(spec)

    AUTH = {"classes": ["state_mutating"], "authorised_by": "Client Lead",
            "authorised_on": "2026-10-01", "reference": "RoE-11"}

    def test_authorisation_permits_only_its_classes(self):
        policy = self.policy(authorisations=[self.AUTH])
        self.assertTrue(policy.permits(FakeCase()))
        self.assertFalse(policy.permits(
            FakeCase(state_mutating=False, volume_class="burst")))

    def test_reason_names_the_authoriser(self):
        policy = self.policy(authorisations=[self.AUTH])
        _, reason = policy.evaluate(FakeCase())
        self.assertIn("Client Lead", reason)
        self.assertIn("RoE-11", reason)

    def test_expired_authorisation_does_not_permit(self):
        auth = dict(self.AUTH, expires_on="2026-01-31")
        self.assertFalse(self.policy(authorisations=[auth]).permits(FakeCase()))

    def test_endpoint_scoped_authorisation(self):
        auth = dict(self.AUTH, endpoints=["create"])
        policy = self.policy(authorisations=[auth])
        self.assertTrue(policy.permits(FakeCase(endpoint="create")))
        self.assertFalse(policy.permits(FakeCase(endpoint="delete")))


class TestScopeFilters(unittest.TestCase):
    def test_endpoint_allow_and_deny_lists(self):
        policy = ScopePolicy({"schema": "scope-policy/1", "deny_classes": [],
                              "deny_endpoints": ["danger"]})
        self.assertFalse(policy.permits(FakeCase(endpoint="danger")))
        self.assertTrue(policy.permits(FakeCase(endpoint="safe")))

        policy = ScopePolicy({"schema": "scope-policy/1", "deny_classes": [],
                              "allow_endpoints": ["only"]})
        self.assertFalse(policy.permits(FakeCase(endpoint="other")))

    def test_method_allowlist(self):
        policy = ScopePolicy({"schema": "scope-policy/1", "deny_classes": [],
                              "allow_methods": ["POST"]})
        self.assertFalse(policy.permits(FakeCase(method="DELETE")))

    def test_risk_ceiling(self):
        policy = ScopePolicy({"schema": "scope-policy/1", "deny_classes": [],
                              "max_risk": "read_only"})
        self.assertFalse(policy.permits(FakeCase()))
        self.assertTrue(policy.permits(FakeCase(state_mutating=False)))

    def test_filter_splits_and_explains(self):
        policy = ScopePolicy.default()
        permitted, skipped = policy.filter(
            [FakeCase("A", state_mutating=False), FakeCase("B")])
        self.assertEqual([c.id for c in permitted], ["A"])
        self.assertEqual(skipped[0][0].id, "B")
        self.assertIn("state_mutating", skipped[0][1])


if __name__ == "__main__":
    unittest.main()


class TestProxyTraversalRequirement(unittest.TestCase):
    """Rules of engagement often require every request to traverse the
    intercepting proxy, so the client has a reviewable record of the traffic.

    ENGINEERING IMPROVEMENT. Scope matched only payload and volume attributes,
    so ``--direct`` and a per-case ``use_proxy`` override were ungoverned: a
    request could leave the recorded path with nothing to stop it and nothing
    to record the decision. ``require_proxy`` closes that, through the same
    authorisation mechanism as every other denied class.
    """

    READ_ONLY = dict(state_mutating=False)

    def policy(self, **over):
        spec = {"schema": "scope-policy/1", "deny_classes": [],
                "require_proxy": True}
        spec.update(over)
        return ScopePolicy(spec)

    def test_absent_by_default_so_direct_runs_are_unaffected(self):
        pol = ScopePolicy({"schema": "scope-policy/1", "deny_classes": []})
        ok, _ = pol.evaluate(FakeCase(**self.READ_ONLY), via_proxy=False)
        self.assertTrue(ok)

    def test_direct_run_is_denied_when_the_proxy_is_required(self):
        ok, reason = self.policy().evaluate(FakeCase(**self.READ_ONLY),
                                            via_proxy=False)
        self.assertFalse(ok)
        self.assertIn("proxy", reason.lower())
        self.assertIn("direct_transport", reason)

    def test_proxied_run_is_permitted(self):
        ok, _ = self.policy().evaluate(FakeCase(**self.READ_ONLY),
                                       via_proxy=True)
        self.assertTrue(ok)

    def test_a_per_case_override_cannot_escape_the_requirement(self):
        case = FakeCase(use_proxy=False, **self.READ_ONLY)
        ok, reason = self.policy().evaluate(case, via_proxy=True)
        self.assertFalse(ok, "case-level use_proxy=False must still be gated")
        self.assertIn("direct_transport", reason)

    def test_an_authorisation_permits_direct_transport_and_is_named(self):
        pol = self.policy(authorisations=[{
            "classes": ["direct_transport"],
            "authorised_by": "Test Operator",
            "authorised_on": "2026-01-01",
            "reference": "ROE-1 s.3 TLS evidence must be captured direct",
        }])
        ok, reason = pol.evaluate(FakeCase(**self.READ_ONLY), via_proxy=False)
        self.assertTrue(ok)
        self.assertIn("Test Operator", reason)

    def test_an_expired_authorisation_does_not_permit_direct_transport(self):
        pol = self.policy(authorisations=[{
            "classes": ["direct_transport"],
            "authorised_by": "Test Operator",
            "authorised_on": "2026-01-01",
            "reference": "ROE-1",
            "expires_on": "2026-01-02",
        }])
        ok, _ = pol.evaluate(FakeCase(**self.READ_ONLY), via_proxy=False,
                             today=__import__("datetime").date(2026, 6, 1))
        self.assertFalse(ok)

    def test_unknown_transport_is_not_silently_treated_as_proxied(self):
        """via_proxy=None means the caller did not say. Enforce nothing rather
        than guess, but a case that explicitly opts out is still caught."""
        pol = self.policy()
        self.assertTrue(pol.evaluate(FakeCase(**self.READ_ONLY))[0])
        self.assertFalse(
            pol.evaluate(FakeCase(use_proxy=False, **self.READ_ONLY))[0])

    def test_filter_and_require_honour_the_transport(self):
        pol = self.policy()
        cases = [FakeCase(cid="A", **self.READ_ONLY)]
        permitted, skipped = pol.filter(cases, via_proxy=False)
        self.assertEqual(len(permitted), 0)
        self.assertEqual(len(skipped), 1)
        with self.assertRaises(AuthorisationError):
            pol.require(cases[0], via_proxy=False)

    def test_schema_accepts_require_proxy(self):
        import json, os, tempfile
        from framework.governance.scope import SCHEMA_PATH  # noqa: F401
        spec = {"schema": "scope-policy/1", "deny_classes": [],
                "require_proxy": True}
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(spec, fh)
        try:
            self.assertTrue(ScopePolicy.load(path).require_proxy)
        finally:
            os.unlink(path)


class TestRunnerHonoursProxyRequirement(unittest.TestCase):
    """The gate is only real if the runner consults it with the transport it
    will actually use. A policy that denies direct transport must stop a
    ``--direct`` run before anything is sent."""

    def _runner(self, via_proxy, policy):
        import os
        import shutil
        import tempfile
        from framework import runner as RUN
        from framework.evidence.store import EvidenceStore
        from tests.support import auth_for, load_profile
        tmp = tempfile.mkdtemp(prefix="apiscan-rp-")
        self.addCleanup(shutil.rmtree, tmp, True)
        profile = load_profile(base_url="https://api.example.com/v1",
                               proxy="http://127.0.0.1:8080")
        store = EvidenceStore(os.path.join(tmp, "evidence"))
        return RUN.Runner(profile, auth_for(profile), store,
                          scope_policy=policy, via_proxy=via_proxy, delay_s=0)

    def policy(self):
        return ScopePolicy({"schema": "scope-policy/1", "deny_classes": [],
                            "require_proxy": True})

    def case(self):
        from framework.corpus.case import Case
        return Case("T01", "resource_create", "reject", "transport probe",
                    body="{}", state_mutating=False)

    def test_a_direct_run_is_skipped_not_sent(self):
        runner = self._runner(via_proxy=False, policy=self.policy())
        rec = runner.run_case(self.case())
        self.assertEqual(rec["verdict"], "SKIPPED")
        self.assertIn("direct_transport", rec["scope_reason"])

    def test_a_proxied_run_is_not_blocked_by_the_requirement(self):
        runner = self._runner(via_proxy=True, policy=self.policy())
        ok, reason = runner.scope.evaluate(self.case(),
                                           via_proxy=runner.via_proxy)
        self.assertTrue(ok, reason)
