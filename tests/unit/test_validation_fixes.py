"""Fixes for discrepancies found by driving the whole pipeline end to end.

Each test pins one defect observed during a full CLI validation run against the
loopback mock on 2026-10-07.
"""
import unittest

from tests.support import ROOT  # noqa: F401


class TestHeadlineTitle(unittest.TestCase):
    """D4. PoC titles were cut with a bare ``description[:90]``, which lands
    mid-word -- "...submitted to 'resource_crea" -- on the client-facing image.
    """

    def helper(self):
        from tools.capture.render import headline_title
        return headline_title

    def test_a_short_title_is_untouched(self):
        self.assertEqual(self.helper()("A01", "short description"),
                         "A01 -- short description")

    def test_a_long_title_breaks_on_a_word_boundary(self):
        ht = self.helper()
        desc = ("Identifier from namespace 'audit_ref' (endpoint "
                "'audit_entry') submitted to 'resource_create' which owns a "
                "different namespace entirely")
        out = ht("A01", desc, limit=90)
        self.assertLessEqual(len(out), 90)
        self.assertTrue(out.endswith("..."), out)
        body = out[:-3].rstrip()
        self.assertFalse(body.endswith("resource_crea"),
                         "must not cut mid-word: %r" % out)
        self.assertTrue(desc.startswith(body.split(" -- ", 1)[1]),
                        "the kept text must be a clean prefix of the original")

    def test_the_case_id_always_survives(self):
        out = self.helper()("VERYLONGCASEID01", "x" * 400, limit=40)
        self.assertTrue(out.startswith("VERYLONGCASEID01"))
        self.assertLessEqual(len(out), 40)

    def test_a_single_unbroken_word_is_still_cut_to_the_limit(self):
        out = self.helper()("A01", "x" * 300, limit=50)
        self.assertLessEqual(len(out), 50)
        self.assertTrue(out.endswith("..."))


class TestControlsAreNotDoubleCounted(unittest.TestCase):
    """D3. The summary table printed the register's authored CONTROL entry
    count under the label "Controls verified as present", while the coverage
    CSV from the same run reported 158 CONTROL-PRESENT cases and a 46.2%
    control-present rate. Both numbers were right; together they read as a
    contradiction in a client deliverable."""

    def model(self):
        from framework.findings.coverage import Coverage
        from framework.findings.register import Register
        from framework.reporting.model import ReportModel
        records = []
        for i in range(8):
            records.append({"case_id": "C%02d" % i, "executed": True,
                            "verdict": "CONTROL-PRESENT",
                            "severity": "Medium", "endpoint": "e"})
        for i in range(2):
            records.append({"case_id": "D%02d" % i, "executed": True,
                            "verdict": "CONTROL-ABSENT",
                            "severity": "High", "endpoint": "e"})
        reg = Register(entries=[], records=records, strict=False)
        model = ReportModel(register=reg, coverage=Coverage(records),
                            engagement="T", target_name="t")
        model.not_established = ["nothing"]
        return model

    def test_the_summary_exposes_both_figures(self):
        sm = self.model().summary()
        self.assertEqual(sm["verified_controls"], 0,
                         "no CONTROL entries were authored")
        self.assertEqual(sm["tally"]["controls_present"], 8,
                         "but eight cases observed a control holding")

    def test_the_markdown_labels_them_distinctly(self):
        from framework.reporting.renderers.markdown import render
        text = render(self.model())
        self.assertNotIn("| Controls verified as present | 0 |", text,
                         "the ambiguous label must be gone")
        self.assertIn("Controls documented in the register", text)
        self.assertIn("Cases where a control held", text)
        self.assertIn("| 8 |", text)


class TestTlsToolingCheck(unittest.TestCase):
    """D5. The dependency table in the docs described the BUILD host, and was
    read as describing the operator's. The preflight check reports the machine
    the assessment actually runs on."""

    def check(self):
        from automation.preflight import checks as PF
        return next(c for c in PF.REGISTRY if c.check_id == "deps.tls")

    def _with_tools(self, tools):
        from automation.preflight import checks as PF
        from framework.modules import tls_posture
        original = tls_posture.tool_availability
        tls_posture.tool_availability = lambda: tools
        self.addCleanup(setattr, tls_posture, "tool_availability", original)
        return self.check().run({}), PF

    def test_openssl_missing_is_a_blocker(self):
        res, PF = self._with_tools({"openssl": None, "nmap": None,
                                    "testssl": None})
        self.assertEqual(res.status, PF.FAIL)
        self.assertIn("install openssl", res.remedy)

    def test_no_cipher_tool_warns_rather_than_passing_silently(self):
        res, PF = self._with_tools({"openssl": "/usr/bin/openssl",
                                    "nmap": None, "testssl": None})
        self.assertEqual(res.status, PF.WARN)
        self.assertIn("NOT VERIFIED", res.detail)

    def test_testssl_alone_satisfies_cipher_enumeration(self):
        """The availability map keys this 'testssl', not 'testssl.sh'."""
        res, PF = self._with_tools({"openssl": "/usr/bin/openssl",
                                    "nmap": None,
                                    "testssl": "/usr/local/bin/testssl.sh"})
        self.assertEqual(res.status, PF.PASS, res.detail)

    def test_nmap_alone_satisfies_cipher_enumeration(self):
        res, PF = self._with_tools({"openssl": "/usr/bin/openssl",
                                    "nmap": "/usr/bin/nmap", "testssl": None})
        self.assertEqual(res.status, PF.PASS, res.detail)


class TestScaffoldPlaceholderDetection(unittest.TestCase):
    """`init-engagement` writes a profile that is syntactically valid and
    fully runnable while still pointing at the synthetic example host. Two
    independent agents ran a scan against it and only noticed afterwards.

    The failure mode is the dangerous direction: real traffic reaches an
    uninvolved third party while the run looks successful. Neither validate
    nor preflight said anything, so the gate says it now.
    """

    def check(self):
        from automation.preflight import checks as PF
        return next(c for c in PF.REGISTRY if c.check_id == "profile.placeholders")

    def _run(self, mutate=None):
        from automation.preflight import checks as PF
        from tests.support import load_profile
        import copy
        import json as _json
        from framework.core import profile as P
        from tests.support import raw_profile, TEST_ENV
        data = copy.deepcopy(raw_profile())
        if mutate:
            mutate(data)
        prof = P.load_data(data, env=dict(TEST_ENV))
        return self.check().run({"profile": prof}), PF

    def test_the_untouched_scaffold_is_flagged(self):
        res, PF = self._run()
        self.assertEqual(res.status, PF.FAIL, res.detail)
        self.assertIn("example.com", res.detail)

    def test_the_replace_me_description_is_flagged(self):
        def mutate(d):
            d["transport"]["base_url"] = "https://real.test/v1"
            d["identity"]["description"] = "REPLACE THIS. Copied from the example."
        res, PF = self._run(mutate)
        self.assertEqual(res.status, PF.FAIL)
        self.assertIn("description", res.detail.lower())

    def test_a_replace_me_engagement_reference_is_flagged(self):
        def mutate(d):
            d["transport"]["base_url"] = "https://real.test/v1"
            d["identity"]["description"] = "A real target."
            d["identity"]["engagement_ref"] = "REPLACE-ME"
        res, PF = self._run(mutate)
        self.assertEqual(res.status, PF.FAIL)

    def test_a_filled_in_profile_passes(self):
        def mutate(d):
            d["transport"]["base_url"] = "https://real.test/v1"
            d["identity"]["name"] = "acme-callback-api"
            d["identity"]["description"] = "The client's callback API."
            d["identity"]["engagement_ref"] = "ACME-2026-001"
        res, PF = self._run(mutate)
        self.assertEqual(res.status, PF.PASS, res.detail)

    def test_the_remedy_is_concrete(self):
        res, _ = self._run()
        self.assertTrue(res.remedy)
        self.assertIn("profile.json", res.remedy)
