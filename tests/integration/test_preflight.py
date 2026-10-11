"""Preflight gate integration.

The gate's value is that the FIRST failure is the thing to fix and that every
failure carries a remedy. Both are asserted here, along with the behaviour that
matters most: a configured-but-absent proxy stops the run before any case is
sent.
"""
import os
import shutil
import tempfile
import unittest

from tests.fixtures.mock_service import MockService
from tests.support import ROOT, auth_for, load_profile  # noqa: F401
from automation.preflight import checks as PF
from framework.core.pathguard import FRAMEWORK_ROOT
from framework.core.transport import Transport


class TestPreflight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-pf-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ctx(self, profile, **kw):
        base = {"profile": profile,
                "evidence_root": os.path.join(self.tmp, "evidence")}
        base.update(kw)
        return base

    def test_healthy_direct_target_is_ready(self):
        with MockService() as svc:
            profile = load_profile(base_url=svc.base_url, proxy=None)
            transport = Transport(profile, auth_for(profile),
                                  body_dir=self.tmp, via_proxy=False)
            results, blocked = PF.run(self.ctx(profile, transport=transport),
                                      quiet=True)
            self.assertFalse(blocked)
            by_id = {r.check_id: r for r in results}
            self.assertEqual(by_id["target.reachable"].status, PF.PASS)
            self.assertEqual(by_id["target.oracle"].status, PF.PASS)

    def test_proxy_checks_are_skipped_when_no_proxy_is_configured(self):
        with MockService() as svc:
            profile = load_profile(base_url=svc.base_url, proxy=None)
            transport = Transport(profile, auth_for(profile),
                                  body_dir=self.tmp, via_proxy=False)
            results, _ = PF.run(self.ctx(profile, transport=transport),
                                quiet=True)
            by_id = {r.check_id: r for r in results}
            for check in ("proxy.listener", "proxy.forwarding", "proxy.ca"):
                self.assertEqual(by_id[check].status, PF.SKIP, check)

    def test_an_absent_proxy_blocks_before_anything_is_sent(self):
        from tests.fixtures.mock_service import STATE
        with MockService() as svc:
            profile = load_profile(base_url=svc.base_url,
                                   proxy="http://127.0.0.1:1")
            before = STATE.requests
            results, blocked = PF.run(self.ctx(profile), quiet=True)
            self.assertTrue(blocked)
            self.assertEqual(results[-1].check_id, "proxy.listener")
            self.assertEqual(results[-1].status, PF.FAIL)
            self.assertEqual(STATE.requests, before,
                             "preflight sent a request despite a blocker")

    def test_stops_at_the_first_blocker_by_default(self):
        profile = load_profile(base_url="http://127.0.0.1:1/v1",
                               proxy="http://127.0.0.1:1")
        stopping, _ = PF.run(self.ctx(profile), stop_on_fail=True, quiet=True)
        continuing, _ = PF.run(self.ctx(profile), stop_on_fail=False,
                               quiet=True)
        self.assertLess(len(stopping), len(continuing))

    def test_every_failure_carries_a_remedy(self):
        profile = load_profile(base_url="http://127.0.0.1:1/v1",
                               proxy="http://127.0.0.1:1")
        results, _ = PF.run(self.ctx(profile), stop_on_fail=False, quiet=True)
        for result in results:
            if result.status == PF.FAIL:
                self.assertTrue(result.remedy,
                                "%s failed with no remedy" % result.check_id)

    def test_evidence_root_inside_the_framework_is_a_blocker(self):
        with MockService() as svc:
            profile = load_profile(base_url=svc.base_url, proxy=None)
            transport = Transport(profile, auth_for(profile),
                                  body_dir=self.tmp, via_proxy=False)
            results, blocked = PF.run(
                {"profile": profile, "transport": transport,
                 "evidence_root": os.path.join(FRAMEWORK_ROOT, "evidence")},
                stop_on_fail=False, quiet=True)
            by_id = {r.check_id: r for r in results}
            self.assertEqual(by_id["evidence.writable"].status, PF.FAIL)
            self.assertTrue(blocked)

    def test_offline_mode_sends_nothing(self):
        from tests.fixtures.mock_service import STATE
        with MockService() as svc:
            profile = load_profile(base_url=svc.base_url, proxy=None)
            before = STATE.requests
            PF.run(self.ctx(profile, offline=True), stop_on_fail=False,
                   quiet=True)
            self.assertEqual(STATE.requests, before)

    def test_json_output_is_machine_readable(self):
        import json
        with MockService() as svc:
            profile = load_profile(base_url=svc.base_url, proxy=None)
            transport = Transport(profile, auth_for(profile),
                                  body_dir=self.tmp, via_proxy=False)
            ctx = self.ctx(profile, transport=transport)
            results, _ = PF.run(ctx, quiet=True)
            payload = json.loads(PF.to_json(results, ctx))
            self.assertIn("ready", payload)
            self.assertEqual(len(payload["checks"]), len(results))

    def test_an_uncalibrated_oracle_warns_rather_than_passing_silently(self):
        """A well-formed request that fails means negative results cannot be
        distinguished from a broken harness."""
        with MockService() as svc:
            profile = load_profile(base_url=svc.base_url, proxy=None)
            # Break the credentials so the baseline cannot succeed.
            for identity in profile.data["auth"]["identities"].values():
                if identity.get("headers"):
                    identity["headers"]["x-client-token"] = "wrong"
            transport = Transport(profile, auth_for(profile),
                                  body_dir=self.tmp, via_proxy=False)
            results, _ = PF.run(self.ctx(profile, transport=transport),
                                stop_on_fail=False, quiet=True)
            by_id = {r.check_id: r for r in results}
            self.assertEqual(by_id["target.oracle"].status, PF.WARN)
            self.assertIn("INCONCLUSIVE", by_id["target.oracle"].remedy)


if __name__ == "__main__":
    unittest.main()
