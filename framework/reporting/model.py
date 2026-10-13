"""The report data model.

EXTRACTED CAPABILITY (CAP-032, CAP-033).

Separating the model from the renderers is the main engineering change from the
source, where the spreadsheet writer *was* the report: layout, aggregation and
prose were interleaved in one script, so the only way to produce a different
format was to write another one, and the data could not be tested without
`openpyxl` installed.

Here the model is plain data, testable with the standard library alone, and
renderers consume it. That also means the xlsx renderer being unavailable
degrades the deliverable to Markdown rather than failing the run.

Report section contracts are enforced: the sections an assessment is most
tempted to omit under time pressure -- coverage limitations, and controls that
held -- are mandatory, and ``validate()`` refuses a report without them.
"""
import datetime

MANDATORY_SECTIONS = (
    "how_the_verdict_was_decided",
    "result",
    "findings",
    "coverage_limitations",
    "scope_note",
)

RECOMMENDED_SECTIONS = (
    "controls_verified",
    "residual_and_new",
    "evidence_index",
)


class ReportModel(object):
    def __init__(self, engagement, target_name, register, coverage,
                 records=None, run_metadata=None, methodology=None,
                 scope_note="", verdict_basis="", generated=None):
        self.engagement = engagement
        self.target_name = target_name
        self.register = register
        self.coverage = coverage
        self.records = list(records or [])
        self.run_metadata = dict(run_metadata or {})
        self.methodology = methodology or {}
        self.scope_note = scope_note
        self.verdict_basis = verdict_basis
        self.generated = generated or datetime.date.today().isoformat()
        self.residual = []
        self.evidence_index = []

    # -- sections --------------------------------------------------------
    def summary(self):
        head = self.register.headline()
        cov = self.coverage.statement()
        return {
            "engagement": self.engagement,
            "target": self.target_name,
            "generated": self.generated,
            "run_id": self.run_metadata.get("run_id", ""),
            "status": cov["status"],
            "confirmed_defects": head["confirmed_defects"],
            "unresolved": head["unresolved"],
            "verified_controls": head["verified_controls"],
            "scope_excluded": head["scope_excluded"],
            "by_severity": head["by_severity"],
            "tally": cov["tally"],
            "percentages": cov["percentages"],
        }

    def how_the_verdict_was_decided(self):
        return self.verdict_basis or (
            "Each case declares, before execution, what a correctly "
            "implemented target must do. The response is attributed to the "
            "layer that answered it -- edge, authentication, method, media "
            "type, validation, business logic, or acceptance -- and the "
            "declared expectation is mapped against that layer to produce a "
            "verdict. HTTP status alone is not treated as a verdict, because "
            "the same status can originate at different layers and because "
            "this target signals outcomes inside the response body. A request "
            "stopped before the application is recorded as BLOCKED and is "
            "never counted as a pass: an unreached test is not evidence about "
            "the control it was intended to probe. No verdict is taken from "
            "any status or remediation claim supplied by the client.")

    def findings_rows(self):
        rows = []
        for e in self.register.sorted_entries():
            d = e.as_dict()
            d["affected"] = ", ".join(d["affected_endpoints"]) or "-"
            d["cases"] = ", ".join(d["case_ids"]) or "-"
            rows.append(d)
        return rows

    def test_log_rows(self):
        """Every case with its disposition. The auditable coverage record."""
        rows = []
        for r in self.records:
            rows.append({
                "case_id": r.get("case_id"),
                "phase": r.get("phase") or "",
                "family": r.get("family") or "",
                "endpoint": r.get("endpoint") or "",
                "method": r.get("method_http") or "",
                "payload_class": r.get("payload_class") or "",
                "expectation": r.get("expectation") or "",
                "executed": "yes" if r.get("executed") else "no",
                "http_status": r.get("http_status") or "",
                "layer": r.get("layer") or "",
                "verdict": r.get("verdict") or "",
                "control_depth": r.get("control_depth") or "",
                "reason": r.get("verdict_reason") or r.get("scope_reason") or "",
                "capture_method": r.get("capture_method") or "",
                "evidence": r.get("response_file") or "",
                "description": r.get("description") or "",
            })
        return rows

    def coverage_limitations(self):
        cov = self.coverage.statement()
        return {
            "status": cov["status"],
            "baseline": cov["baseline"],
            "not_established": cov["not_established"],
            "problems": cov["problems"],
            "skipped_out_of_scope": cov["tally"]["skipped_out_of_scope"],
            "blocked": cov["tally"]["blocked_before_application"],
            "errored": cov["tally"]["errored"],
            "unclear": cov["tally"]["unclear"],
        }

    def controls_verified(self):
        return [e.as_dict() for e in self.register.controls()]

    def section_map(self):
        return {
            "summary": self.summary(),
            "how_the_verdict_was_decided": self.how_the_verdict_was_decided(),
            "result": self.summary(),
            "findings": self.findings_rows(),
            "controls_verified": self.controls_verified(),
            "residual_and_new": self.residual,
            "coverage_limitations": self.coverage_limitations(),
            "controls_improved": self.coverage.controls_improved,
            "scope_note": self.scope_note,
            "test_log": self.test_log_rows(),
            "evidence_index": self.evidence_index,
            "methodology": self.methodology,
        }

    # -- gate ------------------------------------------------------------
    def validate(self):
        problems = []
        sections = self.section_map()
        for name in MANDATORY_SECTIONS:
            value = sections.get(name)
            if value in (None, "", [], {}):
                problems.append("mandatory report section %r is empty" % name)
        limits = self.coverage_limitations()
        if not limits["not_established"]:
            problems.append(
                "coverage_limitations.not_established is empty; the report "
                "must state what the assessment did NOT establish")
        if not self.scope_note:
            problems.append("scope_note is empty; the rules of engagement and "
                            "exclusions must be stated")
        # ENGINEERING IMPROVEMENT (review finding 4). A report is not issuable
        # while any DEFECT row it carries lacks an expectation, an
        # observation, a baseline, evidence, a recommendation or the
        # alternative explanations that were ruled out. These are the elements
        # a client needs in order to disagree with a finding, which is exactly
        # when a report has to hold up.
        problems.extend(self.register.issuable_problems())
        problems.extend(self.coverage.validate())
        return problems

    def is_issuable(self):
        return not self.validate()
