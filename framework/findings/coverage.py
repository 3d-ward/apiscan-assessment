"""Coverage and honesty accounting.

EXTRACTED CAPABILITY (CAP-034, CAP-011).

This module exists to make a specific kind of dishonesty hard. The tempting
summary of an assessment is "N cases, all controls present". That sentence is
true only if every case actually ran. Cases that were skipped for scope, blocked
at an edge control, or errored are *not* evidence about the controls they were
meant to probe, and folding them into a pass rate inflates the result.

So:

  * coverage is computed, never asserted
  * blocked and skipped are reported separately and never counted as passes
  * a run with failing baselines is INCONCLUSIVE regardless of its other results
  * the "not established" list is mandatory. ``validate()`` refuses to certify a
    coverage statement with an empty one, because every assessment has limits
    and the section that states them is the first one dropped under time
    pressure.
"""
from ..oracle import verdict as V

PASS_VERDICTS = (V.CONTROL_PRESENT,)
FAIL_VERDICTS = (V.CONTROL_ABSENT,)
INCONCLUSIVE_VERDICTS = (V.BLOCKED, V.ERROR, V.UNCLEAR)

TESTABILITY_OBSERVABLE = "observable"
TESTABILITY_NOT_EXTERNAL = "not_externally_testable"
TESTABILITY_RISK_ACCEPTED = "risk_accepted"


class Coverage(object):
    def __init__(self, records, planned=None, baseline_ok=None,
                 baseline_summary="", not_established=None,
                 controls_improved=None):
        self.records = list(records or [])
        self.planned = len(planned) if planned is not None else len(self.records)
        self.baseline_ok = baseline_ok
        self.baseline_summary = baseline_summary
        self.not_established = list(not_established or [])
        self.controls_improved = list(controls_improved or [])

    # -- arithmetic ------------------------------------------------------
    def tally(self):
        from ..runner import NOT_REACHED
        recs = self.records
        executed = [r for r in recs if r.get("executed")]
        unexecuted = [r for r in recs if not r.get("executed")]
        # A case the engagement excluded and a case the run never got to are
        # both "not executed", and they mean opposite things about the
        # assessment. Counting them together would let a run that stopped on
        # its third consecutive 500 report the same coverage as one the client
        # deliberately narrowed.
        not_reached = [r for r in unexecuted
                       if r.get("verdict") == NOT_REACHED]
        skipped = [r for r in unexecuted
                   if r.get("verdict") != NOT_REACHED]
        blocked = [r for r in executed if r.get("verdict") == V.BLOCKED]
        errored = [r for r in executed if r.get("verdict") == V.ERROR]
        unclear = [r for r in executed if r.get("verdict") == V.UNCLEAR]
        conclusive = [r for r in executed
                      if r.get("verdict") not in INCONCLUSIVE_VERDICTS]
        passed = [r for r in conclusive if r.get("verdict") in PASS_VERDICTS]
        failed = [r for r in conclusive if r.get("verdict") in FAIL_VERDICTS]
        over = [r for r in conclusive if r.get("verdict") == V.OVER_BLOCKED]
        observed = [r for r in conclusive if r.get("verdict") == V.OBSERVED]

        return {
            "planned": self.planned,
            "executed": len(executed),
            "skipped_out_of_scope": len(skipped),
            "not_reached_run_stopped": len(not_reached),
            "blocked_before_application": len(blocked),
            "errored": len(errored),
            "unclear": len(unclear),
            "conclusive": len(conclusive),
            "controls_present": len(passed),
            "controls_absent": len(failed),
            "over_blocked": len(over),
            "observed_only": len(observed),
        }

    def percentages(self):
        t = self.tally()
        planned = t["planned"] or 1
        executed = t["executed"] or 1
        return {
            # Of everything planned, how much actually ran.
            "execution_coverage_pct": round(100.0 * t["executed"] / planned, 1),
            # Of what ran, how much produced a usable verdict. Blocked and
            # errored cases are excluded from the numerator deliberately.
            "conclusive_pct": round(100.0 * t["conclusive"] / executed, 1),
            # Of the conclusive cases, how many found the control present.
            # NOT a security score -- a corpus is mostly negative tests.
            "control_present_pct": (
                round(100.0 * t["controls_present"] / t["conclusive"], 1)
                if t["conclusive"] else 0.0),
        }

    # -- honesty gates ---------------------------------------------------
    def status(self):
        """Overall run status, honouring the baseline gate."""
        t = self.tally()
        if self.baseline_ok is False:
            return "INCONCLUSIVE"
        if t["not_reached_run_stopped"]:
            # The run stopped early. Whatever it found may be sound, but the
            # assessment is not complete and must not read as though it were.
            return "INCOMPLETE"
        if t["executed"] == 0:
            return "NOT EXECUTED"
        if t["conclusive"] == 0:
            return "INCONCLUSIVE"
        if t["over_blocked"]:
            # A legitimate request being refused means the harness, the
            # credentials or the target state may be wrong, which casts doubt
            # on every negative result in the run.
            return "QUALIFIED"
        return "COMPLETE"

    def validate(self):
        """Problems that must be resolved before a report may be issued."""
        problems = []
        t = self.tally()
        if self.baseline_ok is None:
            problems.append(
                "baseline calibration was not assessed; without it a negative "
                "result cannot be distinguished from a broken harness")
        elif self.baseline_ok is False:
            problems.append("baseline calibration failed: %s"
                            % self.baseline_summary)
        if not self.not_established:
            problems.append(
                "the 'not established' list is empty; every assessment has "
                "limits and they must be stated explicitly")
        if t["blocked_before_application"] and t["conclusive"] == 0:
            problems.append(
                "every executed case was blocked before reaching the "
                "application; this run is evidence about the edge control only")
        if t["over_blocked"]:
            problems.append(
                "%d case(s) declared legitimate were refused (OVER-BLOCKED); "
                "explain this before relying on the negative results"
                % t["over_blocked"])
        if t["not_reached_run_stopped"]:
            problems.append(
                "%d case(s) were never sent because the run hit a ceiling or "
                "a stop condition; the assessment is incomplete and the "
                "untested cases must be listed as not established"
                % t["not_reached_run_stopped"])
        return problems

    # -- matrices --------------------------------------------------------
    def matrix(self, row="phase", col="endpoint"):
        out = {}
        for r in self.records:
            a, b = r.get(row), r.get(col)
            out.setdefault(a, {}).setdefault(b, {"executed": 0, "present": 0,
                                                 "absent": 0, "skipped": 0,
                                                 "blocked": 0})
            cell = out[a][b]
            if not r.get("executed"):
                cell["skipped"] += 1
                continue
            cell["executed"] += 1
            v = r.get("verdict")
            if v == V.CONTROL_PRESENT:
                cell["present"] += 1
            elif v == V.CONTROL_ABSENT:
                cell["absent"] += 1
            elif v == V.BLOCKED:
                cell["blocked"] += 1
        return out

    def untested_cells(self, rows, cols, row_attr="phase", col_attr="endpoint"):
        m = self.matrix(row_attr, col_attr)
        return [(r, c) for r in rows for c in cols
                if m.get(r, {}).get(c, {}).get("executed", 0) == 0]

    # -- rendering input -------------------------------------------------
    def statement(self):
        """The coverage block a report embeds."""
        t = self.tally()
        p = self.percentages()
        return {
            "status": self.status(),
            "tally": t,
            "percentages": p,
            "baseline": {"ok": self.baseline_ok,
                         "summary": self.baseline_summary},
            "not_established": self.not_established,
            "controls_improved": self.controls_improved,
            "problems": self.validate(),
        }


def remediation_testability(items):
    """Split typed remediation items into what a retest can and cannot claim.

    EXTRACTED CAPABILITY (CAP-034). Items that are documentation or internal
    process are not externally testable; a retest that reports them as verified
    is overclaiming. Risk-accepted items are not remediations at all and must
    not be closed as such.
    """
    observable, untestable, accepted = [], [], []
    for item in items or []:
        kind = item.get("kind")
        if kind == TESTABILITY_OBSERVABLE:
            observable.append(item)
        elif kind == TESTABILITY_RISK_ACCEPTED:
            accepted.append(item)
        else:
            untestable.append(item)
    return {
        "observable": observable,
        "not_externally_testable": untestable,
        "risk_accepted": accepted,
        "claimable_pct": (round(100.0 * len(observable) / len(items), 1)
                          if items else 0.0),
    }
