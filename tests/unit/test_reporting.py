import os
import shutil
import tempfile
import unittest

from tests.support import ROOT  # noqa: F401
from framework.core.errors import RegisterError
from framework.findings.coverage import Coverage, remediation_testability
from framework.findings.register import (Entry, KIND_CONTROL, KIND_UNRESOLVED,
                                         Register)
from framework.oracle import verdict as V
from framework.reporting.model import ReportModel
from framework.reporting.renderers import csvout, markdown, xlsx


def record(case_id, verdict, **kw):
    base = {"case_id": case_id, "verdict": verdict, "executed": True,
            "endpoint": kw.pop("endpoint", "create"), "detector_hits": [],
            "severity_if_accepted": kw.pop("severity", "Medium"),
            "payload_class": kw.pop("payload_class", "benign"),
            "layer": kw.pop("layer", "accepted_success"),
            "response_file": "%s.resp.txt" % case_id}
    base.update(kw)
    return base



def defect(id, title, **kw):
    """A DEFECT row carrying the elements an issuable defect must carry.

    The register refuses a DEFECT at ``suspected`` confidence and a report
    refuses to be issuable when a DEFECT row states no expectation, no
    observation, no recommendation or no alternative explanations. That is the
    point of those rules, so the fixture supplies them rather than the tests
    routing around them.
    """
    kw.setdefault("confidence", "reproduced")
    kw.setdefault("expected_behaviour",
                  "A correct target rejects input of this class.")
    kw.setdefault("observed_behaviour",
                  "The target accepted it and answered 200.")
    kw.setdefault("recommendation",
                  "Validate the field against an explicit schema.")
    kw.setdefault("alternative_explanations",
                  ["the input may be neutralised downstream where this "
                   "assessment cannot observe it"])
    return Entry(id, title, **kw)


RECORDS = [
    record("BASE-create", V.CONTROL_PRESENT, layer="accepted_success"),
    record("A01", V.CONTROL_ABSENT, endpoint="create"),
    record("A02", V.CONTROL_ABSENT, endpoint="update"),
    record("C01", V.CONTROL_PRESENT, layer="validation_reject"),
    record("E01", V.BLOCKED, layer="edge_block"),
    record("X01", V.ERROR, layer="server_error"),
    record("S01", "SKIPPED", executed=False, layer=None,
           scope_reason="denied class(es) state_mutating"),
]


class TestRegister(unittest.TestCase):
    def test_aggregates_are_derived(self):
        reg = Register(records=RECORDS)
        reg.add(defect("D-01", "t", case_ids=["A01", "A02"]))
        reg.build()
        entry = reg.entries[0]
        self.assertEqual(entry.occurrences, 2)
        self.assertEqual(entry.affected_endpoints, ["create", "update"])
        self.assertEqual(entry.endpoint_count, 2)

    def test_stale_case_reference_fails_loudly(self):
        reg = Register(records=RECORDS)
        reg.add(defect("D-01", "t", case_ids=["NOPE"]))
        with self.assertRaises(RegisterError):
            reg.build()

    def test_lax_mode_records_the_problem_instead_of_raising(self):
        reg = Register(records=RECORDS, strict=False)
        reg.add(defect("D-01", "t", case_ids=["NOPE"]))
        reg.build()
        self.assertIn("absent from the run data", reg.entries[0].notes)

    def test_duplicate_entry_ids_rejected(self):
        reg = Register(records=RECORDS)
        reg.add(defect("D-01", "t"))
        with self.assertRaises(RegisterError):
            reg.add(defect("D-01", "u"))

    def test_kinds_are_counted_separately(self):
        reg = Register(records=RECORDS)
        reg.add(defect("D-01", "defect", case_ids=["A01"]))
        reg.add(Entry("U-01", "unresolved", kind=KIND_UNRESOLVED))
        reg.add(Entry("V-01", "control held", kind=KIND_CONTROL))
        reg.build()
        head = reg.headline()
        self.assertEqual(head["confirmed_defects"], 1)
        self.assertEqual(head["unresolved"], 1)
        self.assertEqual(head["verified_controls"], 1)

    def test_machine_findings_are_grouped_not_one_row_per_case(self):
        reg = Register(records=RECORDS).promote_machine_findings()
        reg.build()
        # Promoted rows are UNRESOLVED/suspected now, not confirmed defects:
        # a CONTROL-ABSENT verdict is an observation, not a proven weakness.
        self.assertEqual(len(reg.confirmed()), 0)
        promoted = [e for e in reg.entries if e.provenance == "MACHINE"]
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0].kind, KIND_UNRESOLVED)
        self.assertEqual(promoted[0].confidence, "suspected")
        self.assertTrue(promoted[0].alternative_explanations,
                        "a suspected finding must list what else could "
                        "explain the observation")
        self.assertEqual(promoted[0].occurrences, 2)

    def test_invalid_severity_or_kind_rejected(self):
        with self.assertRaises(RegisterError):
            Entry("X", "t", severity="Catastrophic")
        with self.assertRaises(RegisterError):
            Entry("X", "t", kind="MAYBE")


class TestCoverage(unittest.TestCase):
    def cov(self, **kw):
        kw.setdefault("baseline_ok", True)
        kw.setdefault("not_established", ["TLS not assessed."])
        return Coverage(RECORDS, **kw)

    def test_blocked_and_skipped_are_not_passes(self):
        tally = self.cov().tally()
        self.assertEqual(tally["controls_present"], 2)
        self.assertEqual(tally["blocked_before_application"], 1)
        self.assertEqual(tally["skipped_out_of_scope"], 1)
        self.assertEqual(tally["errored"], 1)
        self.assertEqual(tally["conclusive"], 4)

    def test_percentages_exclude_blocked_from_conclusive(self):
        pct = self.cov().percentages()
        self.assertEqual(pct["execution_coverage_pct"], 85.7)
        self.assertLess(pct["conclusive_pct"], 100.0)

    def test_failing_baseline_makes_the_run_inconclusive(self):
        self.assertEqual(self.cov(baseline_ok=False).status(), "INCONCLUSIVE")

    def test_over_blocked_qualifies_the_run(self):
        records = RECORDS + [record("O01", V.OVER_BLOCKED)]
        cov = Coverage(records, baseline_ok=True, not_established=["x"])
        self.assertEqual(cov.status(), "QUALIFIED")
        self.assertTrue(any("OVER-BLOCKED" in p for p in cov.validate()))

    def test_empty_not_established_is_a_validation_failure(self):
        self.assertTrue(any("not established" in p
                            for p in self.cov(not_established=[]).validate()))

    def test_unassessed_baseline_is_a_validation_failure(self):
        self.assertTrue(any("baseline" in p
                            for p in self.cov(baseline_ok=None).validate()))

    def test_remediation_testability_split(self):
        split = remediation_testability([
            {"kind": "observable"}, {"kind": "not_externally_testable"},
            {"kind": "risk_accepted"}])
        self.assertEqual(len(split["observable"]), 1)
        self.assertEqual(len(split["not_externally_testable"]), 1)
        self.assertEqual(len(split["risk_accepted"]), 1)
        self.assertAlmostEqual(split["claimable_pct"], 33.3)


class TestReportModelAndRenderers(unittest.TestCase):
    def build(self, **cov_kw):
        reg = Register(records=RECORDS)
        reg.add(defect("D-01", "Identifier namespace not validated",
                       case_ids=["A01", "A02"], severity="High",
                       description="d", impact="i", recommendation="r"))
        reg.add(Entry("V-01", "Media-type validation holds", kind=KIND_CONTROL,
                      severity="Informational", description="held",
                      observed_behaviour="Every media-type bypass attempt was "
                                         "refused at the media-type layer.",
                      conclusion="No bypass identified."))
        reg.build()
        cov_kw.setdefault("baseline_ok", True)
        cov_kw.setdefault("not_established", ["TLS was not assessed."])
        return ReportModel("eng", "target", reg, Coverage(RECORDS, **cov_kw),
                           records=RECORDS, scope_note="Loopback only.")

    def test_mandatory_sections_gate_issuance(self):
        self.assertTrue(self.build().is_issuable())
        self.assertFalse(self.build(not_established=[]).is_issuable())
        model = self.build()
        model.scope_note = ""
        self.assertFalse(model.is_issuable())

    def test_test_log_covers_every_record(self):
        self.assertEqual(len(self.build().test_log_rows()), len(RECORDS))

    def test_markdown_contains_the_honesty_sections(self):
        text = markdown.render(self.build())
        for heading in ("## Result", "## How the verdict was decided",
                        "## Findings", "## Controls verified as present",
                        "## Coverage limitations", "## Scope note",
                        "## Test log"):
            self.assertIn(heading, text)
        self.assertIn("TLS was not assessed", text)
        # The renderer hard-wraps prose, so compare on normalised whitespace.
        flat = " ".join(text.split())
        self.assertIn("are not counted as controls present", flat)
        self.assertIn("An unreached test is not evidence", flat)

    def test_markdown_warns_when_a_report_is_not_issuable(self):
        self.assertIn("not issuable",
                      markdown.render(self.build(not_established=[])))

    def test_csv_outputs(self):
        out = tempfile.mkdtemp(prefix="apiscan-csv-")
        try:
            written = csvout.write(self.build(), out)
            self.assertEqual(len(written), 3)
            with open(written[1]) as fh:
                self.assertEqual(len(fh.read().splitlines()),
                                 len(RECORDS) + 1)
        finally:
            shutil.rmtree(out, ignore_errors=True)

    @unittest.skipUnless(xlsx.available(), "openpyxl not installed")
    def test_xlsx_has_the_expected_sheets(self):
        out = tempfile.mkdtemp(prefix="apiscan-xlsx-")
        try:
            path = os.path.join(out, "r.xlsx")
            result = xlsx.write(self.build(), path)
            self.assertEqual(result.sheets,
                             ["Summary", "Findings", "Test Log", "Coverage"])
            import openpyxl
            wb = openpyxl.load_workbook(path)
            self.assertEqual(wb["Test Log"].max_row, len(RECORDS) + 1)
        finally:
            shutil.rmtree(out, ignore_errors=True)

    @unittest.skipUnless(xlsx.available(), "openpyxl not installed")
    def test_missing_pillow_is_reported_not_silently_skipped(self):
        out = tempfile.mkdtemp(prefix="apiscan-xlsx-")
        try:
            result = xlsx.write(
                self.build(), os.path.join(out, "r.xlsx"),
                poc_images=[{"finding_id": "D-01", "path": "/nope.png",
                             "capture_method": "derived"}])
            if not xlsx.pillow_available():
                self.assertEqual(result.images_embedded, 0)
                self.assertTrue(any("Pillow" in n for n in result.notes))
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_xlsx_absence_raises_a_typed_dependency_error(self):
        if xlsx.available():
            self.skipTest("openpyxl is installed")
        from framework.core.errors import DependencyUnavailable
        with self.assertRaises(DependencyUnavailable):
            xlsx.write(self.build(), "/tmp/x.xlsx")


if __name__ == "__main__":
    unittest.main()


class TestHeadlineNomination(unittest.TestCase):
    """One decisive PoC per finding, chosen deterministically. Hand-nomination
    does not scale and degrades silently as a corpus grows."""

    RECORDS = [
        record("A03", V.CONTROL_ABSENT, layer="business_reject",
               severity="High"),
        record("A01", V.CONTROL_ABSENT, layer="accepted_success",
               severity="Medium"),
        record("A02", V.CONTROL_ABSENT, layer="validation_reject",
               severity="High",
               detector_hits=[{"rule_id": "DISC-SQL", "severity": "High"}]),
    ]

    def reg(self, records, case_ids):
        r = Register(records=records)
        r.add(defect("D-01", "t", case_ids=case_ids))
        r.build()
        return r

    def test_detector_hit_wins(self):
        r = self.reg(self.RECORDS, ["A01", "A02", "A03"])
        self.assertEqual(r.headline_case(r.entries[0])["case_id"], "A02")

    def test_otherwise_the_most_decisive_layer_wins(self):
        records = [x for x in self.RECORDS if x["case_id"] != "A02"]
        r = self.reg(records, ["A01", "A03"])
        self.assertEqual(r.headline_case(r.entries[0])["case_id"], "A01")

    def test_selection_is_stable(self):
        r = self.reg(self.RECORDS, ["A01", "A02", "A03"])
        first = r.headline_case(r.entries[0])["case_id"]
        for _ in range(5):
            self.assertEqual(r.headline_case(r.entries[0])["case_id"], first)

    def test_entry_with_no_rows_returns_none(self):
        r = Register(records=self.RECORDS)
        r.add(defect("D-02", "t"))
        r.build()
        self.assertIsNone(r.headline_case(r.entries[0]))

    def test_index_is_one_row_per_entry(self):
        r = self.reg(self.RECORDS, ["A01", "A02", "A03"])
        index = r.headline_index()
        self.assertEqual(len(index), 1)
        self.assertEqual(index[0]["selection"], "deterministic")
        self.assertTrue(index[0]["has_detector_hit"])
