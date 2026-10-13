"""End-to-end integration against a loopback mock.

No outbound network access: the mock binds to 127.0.0.1 on an ephemeral port
and resolves no names. These tests prove the pipeline finds the defects that
were deliberately planted, and -- just as importantly -- does NOT invent
findings against the same service in strict mode.
"""
import json
import os
import shutil
import tempfile
import unittest

from tests.fixtures.mock_service import MockService
from tests.support import ROOT, auth_for, load_profile  # noqa: F401
from framework import runner as RUN
from framework.corpus.case import Corpus
from framework.corpus.generators import families as F
from framework.corpus.generators import phases as G
from framework.corpus.generators import retest as RT
from framework.evidence.store import EvidenceStore
from framework.governance.scope import ScopePolicy
from framework.oracle import verdict as V

PERMISSIVE_SCOPE = {
    "schema": "scope-policy/1",
    "deny_classes": ["volumetric", "destructive"],
    "authorisations": [{
        "classes": ["state_mutating"], "authorised_by": "Test Harness",
        "authorised_on": "2026-10-06", "reference": "SELFTEST",
    }],
}


class BaseRun(unittest.TestCase):
    strict = False

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="apiscan-it-")
        cls.service = MockService(strict=cls.strict)
        cls.service.__enter__()
        cls.profile = load_profile(base_url=cls.service.base_url, proxy=None)
        cls.auth = auth_for(cls.profile)
        cases = (RT.baseline_cases(cls.profile)
                 + F.generate(cls.profile, auth_provider=cls.auth)
                 + G.generate(cls.profile, cls.auth,
                              phase_ids=["P1", "P2", "P3", "P5"]))
        cls.corpus = Corpus(cases, "integration")
        cls.store = EvidenceStore(os.path.join(cls.tmp, "evidence"),
                                  metadata={"target": cls.profile.name})
        runner = RUN.Runner(cls.profile, cls.auth, cls.store,
                            scope_policy=ScopePolicy(PERMISSIVE_SCOPE),
                            via_proxy=False, delay_s=0)
        cls.records = runner.run(list(cls.corpus))
        cls.store.finalise()
        cls.by_id = {r["case_id"]: r for r in cls.records}

    @classmethod
    def tearDownClass(cls):
        cls.service.__exit__(None, None, None)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def verdicts_for(self, predicate):
        return [r["verdict"] for r in self.records if predicate(r)]


class TestAgainstImperfectTarget(BaseRun):
    strict = False

    def test_baseline_calibrates(self):
        ok, summary = RT.assess_baseline(self.records)
        self.assertTrue(ok, summary)

    def test_evidence_manifest_is_intact(self):
        self.assertEqual(EvidenceStore.verify(self.store.run_dir), [])

    def test_every_case_has_a_disposition(self):
        self.assertEqual(len(self.records), len(self.corpus))
        for rec in self.records:
            self.assertIn(rec["verdict"], list(V.ALL) + [RUN.SKIPPED])

    def test_planted_sql_disclosure_is_detected(self):
        hits = [h["rule_id"] for r in self.records
                for h in (r.get("detector_hits") or [])]
        self.assertIn("DISC-SQL", hits)

    def test_planted_mass_assignment_is_detected(self):
        absent = [r for r in self.records
                  if r.get("phase") == "P5"
                  and r["verdict"] == V.CONTROL_ABSENT]
        self.assertTrue(absent, "mass assignment should have been accepted")

    def test_planted_cross_namespace_substitution_is_detected(self):
        absent = [r for r in self.records
                  if r.get("family") == "A"
                  and r["verdict"] == V.CONTROL_ABSENT]
        self.assertTrue(absent)

    def test_planted_identifier_binding_defect_is_detected(self):
        absent = [r for r in self.records
                  if r.get("phase") == "P3"
                  and r["verdict"] == V.CONTROL_ABSENT]
        self.assertTrue(absent)

    def test_working_controls_are_recorded_as_present(self):
        """The mock enforces auth, method and media type correctly. A scanner
        that cannot see a working control is as useless as one that cannot see
        a broken one."""
        for payload_class in ("auth", "method", "media_type"):
            verdicts = self.verdicts_for(
                lambda r, p=payload_class: r.get("payload_class") == p)
            self.assertIn(V.CONTROL_PRESENT, verdicts, payload_class)

    def test_out_of_scope_cases_were_not_executed(self):
        skipped = [r for r in self.records if r["verdict"] == RUN.SKIPPED]
        self.assertTrue(skipped)
        for rec in skipped:
            self.assertFalse(rec["executed"])
            self.assertIsNone(rec["http_status"])

    def test_no_case_errored_or_was_unclear(self):
        for bad in (V.ERROR,):
            self.assertEqual([r["case_id"] for r in self.records
                              if r["verdict"] == bad], [])

    def test_reclassification_reproduces_the_live_verdicts(self):
        """Offline re-judgement must agree with the live run, or the evidence
        does not support the conclusions drawn from it."""
        replayed = RUN.reclassify(self.store.run_dir, list(self.corpus),
                                  self.profile)
        live = {r["case_id"]: r["verdict"] for r in self.records
                if r["executed"]}
        for rec in replayed:
            self.assertEqual(rec["verdict"], live[rec["case_id"]],
                             rec["case_id"])
        self.assertEqual(len(replayed), len(live))


class TestAgainstStrictTarget(BaseRun):
    strict = True

    def test_baseline_still_calibrates(self):
        ok, summary = RT.assess_baseline(self.records)
        self.assertTrue(ok, summary)

    def test_no_disclosure_is_invented(self):
        hits = [h["rule_id"] for r in self.records
                for h in (r.get("detector_hits") or [])]
        self.assertEqual(hits, [], "detectors fired against a clean target")

    def test_mass_assignment_is_now_a_control_present(self):
        verdicts = self.verdicts_for(lambda r: r.get("phase") == "P5")
        self.assertNotIn(V.CONTROL_ABSENT, verdicts)

    def test_strict_target_yields_far_fewer_findings(self):
        absent = sum(1 for r in self.records
                     if r["verdict"] == V.CONTROL_ABSENT)
        self.assertLess(absent, 20,
                        "a hardened target should not produce a large finding "
                        "count; got %d" % absent)


class TestReportPipeline(BaseRun):
    strict = False

    def test_report_is_issuable_only_with_its_honesty_sections(self):
        from framework.findings.coverage import Coverage
        from framework.findings.register import Register
        from framework.reporting.model import ReportModel
        from framework.reporting.renderers import csvout, markdown

        ok, summary = RT.assess_baseline(self.records)
        register = Register(records=self.records).promote_machine_findings()
        register.build()

        bare = ReportModel("eng", "target", register,
                           Coverage(self.records, baseline_ok=ok,
                                    baseline_summary=summary),
                           records=self.records)
        self.assertFalse(bare.is_issuable())
        self.assertTrue(any("not establish" in p for p in bare.validate()))

        complete = ReportModel(
            "eng", "target", register,
            Coverage(self.records, baseline_ok=ok, baseline_summary=summary,
                     not_established=["TLS was not assessed."]),
            records=self.records, scope_note="Loopback mock only.")
        self.assertTrue(complete.is_issuable(), complete.validate())

        out = tempfile.mkdtemp(prefix="apiscan-rep-")
        try:
            path = markdown.write(complete, os.path.join(out, "r.md"))
            with open(path) as fh:
                text = fh.read()
            self.assertIn("Coverage limitations", text)
            self.assertIn("TLS was not assessed", text)
            written = csvout.write(complete, out)
            self.assertEqual(len(written), 3)
            with open(written[1]) as fh:
                self.assertEqual(len(fh.read().splitlines()),
                                 len(self.records) + 1)
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_register_aggregates_are_derived_not_asserted(self):
        from framework.findings.register import Entry, Register
        from framework.core.errors import RegisterError
        ids = [r["case_id"] for r in self.records
               if r.get("family") == "A"][:3]
        register = Register(records=self.records)
        register.add(Entry("D-01", "t", case_ids=ids,
                           confidence="reproduced"))
        register.build()
        entry = register.entries[0]
        self.assertEqual(entry.occurrences, len(ids))
        self.assertTrue(entry.affected_endpoints)

        stale = Register(records=self.records)
        stale.add(Entry("D-02", "t", case_ids=["NO-SUCH-CASE"],
                        confidence="reproduced"))
        with self.assertRaises(RegisterError):
            stale.build()


if __name__ == "__main__":
    unittest.main()
