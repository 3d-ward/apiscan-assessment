"""Markdown report renderer. Standard library only.

This is the fallback that makes the reporting capability degrade rather than
fail: it needs no third-party package, so a report can always be produced.
"""
import json

from . import safe


#: Spelled out rather than printed as a bare word. "suspected" in a severity
#: table is read as a hedge; the sentence is read as a statement about how
#: much work stands behind the row.
CONFIDENCE_PHRASES = {
    "suspected": "SUSPECTED -- observed automatically; not reproduced, and "
                 "no impact demonstrated",
    "reproduced": "REPRODUCED -- observed again deliberately, with a working "
                  "baseline alongside it",
    "manually-confirmed": "MANUALLY CONFIRMED -- a human drove the path and "
                          "observed the consequence",
}


def _confidence_phrase(value):
    return CONFIDENCE_PHRASES.get(value, value or "not stated")


def _sev_table(counts):
    order = ["Critical", "High", "Medium", "Low", "Informational"]
    rows = ["| Severity | Confirmed |", "|---|---|"]
    for s in order:
        rows.append("| %s | %d |" % (s, counts.get(s, 0)))
    return "\n".join(rows)


def render(model):
    s = model.section_map()
    sm = s["summary"]
    out = []
    A = out.append

    A("# %s -- API security assessment" % sm["engagement"])
    A("")
    A("Target: **%s**  |  Generated: %s  |  Run: `%s`"
      % (sm["target"], sm["generated"], sm["run_id"] or "n/a"))
    A("")
    A("Run status: **%s**" % sm["status"])
    A("")

    problems = model.validate()
    if problems:
        A("> **This report is not issuable as it stands.** The following must")
        A("> be resolved first:")
        A(">")
        for p in problems:
            A("> - %s" % p)
        A("")

    A("## Result")
    A("")
    A("| Measure | Value |")
    A("|---|---|")
    A("| Confirmed defects | %d |" % sm["confirmed_defects"])
    A("| Unresolved (impact not externally provable) | %d |" % sm["unresolved"])
    A("| Controls documented in the register | %d |" % sm["verified_controls"])
    A("| Scope-excluded items | %d |" % sm["scope_excluded"])
    t, p = sm["tally"], sm["percentages"]
    A("| Cases where a control held (CONTROL-PRESENT) | %d |"
      % t["controls_present"])
    A("| Cases planned / executed | %d / %d |" % (t["planned"], t["executed"]))
    A("| Skipped (out of scope) | %d |" % t["skipped_out_of_scope"])
    A("| Blocked before the application | %d |"
      % t["blocked_before_application"])
    A("| Errored / unclear | %d / %d |" % (t["errored"], t["unclear"]))
    A("| Conclusive cases | %d |" % t["conclusive"])
    A("| Execution coverage | %.1f%% |" % p["execution_coverage_pct"])
    A("| Conclusive proportion of executed | %.1f%% |" % p["conclusive_pct"])
    A("")
    A(_sev_table(sm["by_severity"]))
    A("")
    A("Two different things are counted above and they are not "
      "interchangeable. *Controls documented in the register* is the number "
      "of distinct controls written up as findings-register entries; "
      "*cases where a control held* is the number of individual test cases "
      "whose verdict was CONTROL-PRESENT. Many cases can evidence one "
      "control, and a control that held is only written up when it is worth "
      "reporting, so the first number is usually the smaller.")
    A("")
    A("Blocked and skipped cases are reported separately above and are not")
    A("counted as controls present. An unreached test is not evidence about")
    A("the control it was intended to probe.")
    A("")

    A("## How the verdict was decided")
    A("")
    A(s["how_the_verdict_was_decided"])
    A("")

    A("## Findings")
    A("")
    rows = s["findings"]
    if not rows:
        A("No register entries.")
        A("")
    for r in rows:
        A("### %s -- %s" % (r["id"], r["title"]))
        A("")
        A("| | |")
        A("|---|---|")
        A("| Kind | %s |" % r["kind"])
        A("| Confidence | %s |" % _confidence_phrase(r["confidence"]))
        A("| Severity | %s |" % r["severity"])
        A("| Category | %s |" % (r["category"] or "-"))
        A("| CWE | %s |" % (r["cwe"] or "-"))
        A("| OWASP | %s |" % (r["owasp"] or "-"))
        A("| Affected endpoints | %s (%d) |"
          % (r["affected"], r["endpoint_count"]))
        A("| Occurrences | %d |" % r["occurrences"])
        A("| Supporting cases | %s |" % r["cases"])
        A("| Provenance | %s |" % r["provenance"])
        if r["capture_methods"]:
            A("| Evidence capture method | %s |"
              % ", ".join(r["capture_methods"]))
        A("")
        # Expected and observed are stated separately and in that order. A
        # single "description" lets the two blur together, and a reader cannot
        # then tell the declared contract from the thing that happened.
        if r["expected_behaviour"]:
            A("**Expected behaviour.** %s" % safe.md(r["expected_behaviour"]))
            A("")
        if r["observed_behaviour"]:
            A("**Observed behaviour.** %s" % safe.md(r["observed_behaviour"]))
            A("")
        if r["baseline_reference"]:
            A("**Baseline.** %s" % safe.md(r["baseline_reference"]))
            A("")
        else:
            A("**Baseline.** None recorded for the affected endpoints. "
              "Without a working baseline a rejection cannot be "
              "distinguished from a broken harness, and an acceptance cannot "
              "be distinguished from a target that accepts everything.")
            A("")
        if r["state_verification"]:
            A("**Resulting state.** %s" % safe.md(r["state_verification"]))
            A("")
        if r["description"] and r["description"] != r["observed_behaviour"]:
            A("**Description.** %s" % safe.md(r["description"]))
            A("")
        if r["impact"]:
            A("**Impact.** %s" % safe.md(r["impact"]))
            A("")
        if r["alternative_explanations"]:
            A("**Other explanations considered.** A finding is only as strong "
              "as the explanations ruled out:")
            A("")
            for item in r["alternative_explanations"]:
                A("- %s" % safe.md(item))
            A("")
        if r["limitations"]:
            A("**Limitations of this finding.**")
            A("")
            for item in r["limitations"]:
                A("- %s" % safe.md(item))
            A("")
        if r["recommendation"]:
            A("**Recommendation.** %s" % safe.md(r["recommendation"]))
            A("")
        if r["conclusion"]:
            A("**Conclusion.** %s" % safe.md(r["conclusion"]))
            A("")
        if r["evidence_files"]:
            A("Evidence:")
            for f in r["evidence_files"]:
                A("- `%s`" % safe.md(f))
            A("")
        if r["notes"]:
            A("_%s_" % safe.md(r["notes"]))
            A("")

    controls = s["controls_verified"]
    A("## Controls verified as present")
    A("")
    if controls:
        A("These controls were attacked and held. They are reported because")
        A("evidence that a control works is part of the assessment result, and")
        A("because it distinguishes a tested control from an untested one.")
        A("")
        for c in controls:
            A("- **%s** -- %s" % (c["title"], c["description"]))
            if c["conclusion"]:
                A("  - %s" % c["conclusion"])
        A("")
    else:
        A("None recorded.")
        A("")

    if s["residual_and_new"]:
        A("## Residual and newly identified issues")
        A("")
        for r in s["residual_and_new"]:
            A("- **%s** -- %s" % (r.get("id", "?"), r.get("title", "")))
            if r.get("detail"):
                A("  - %s" % r["detail"])
        A("")

    if s["controls_improved"]:
        A("## Controls that improved and are not in the issue log")
        A("")
        for c in s["controls_improved"]:
            A("- %s" % c)
        A("")

    A("## Coverage limitations -- what this assessment did NOT establish")
    A("")
    lim = s["coverage_limitations"]
    A("Run status: **%s**" % lim["status"])
    A("")
    base = lim["baseline"]
    A("Baseline calibration: %s -- %s"
      % ("PASSED" if base["ok"] else "NOT PASSED", base["summary"] or "n/a"))
    A("")
    for item in lim["not_established"]:
        A("- %s" % item)
    A("")
    if lim["problems"]:
        A("Outstanding issues with this run:")
        A("")
        for prob in lim["problems"]:
            A("- %s" % prob)
        A("")

    A("## Scope note")
    A("")
    A(s["scope_note"] or "_Not stated._")
    A("")

    A("## Test log")
    A("")
    A("| Case | Phase | Endpoint | Expect | Exec | Status | Layer | Verdict |")
    A("|---|---|---|---|---|---|---|---|")
    for r in s["test_log"]:
        A("| %s | %s | %s | %s | %s | %s | %s | %s |"
          % (r["case_id"], r["phase"] or "-", r["endpoint"], r["expectation"],
             r["executed"], r["http_status"] or "-", r["layer"] or "-",
             r["verdict"]))
    A("")

    if s["methodology"]:
        A("## Methodology")
        A("")
        A("```json")
        A(json.dumps(s["methodology"], indent=2))
        A("```")
        A("")

    return "\n".join(out)


def write(model, path):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(model))
    return path
