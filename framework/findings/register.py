"""The findings register: one row per distinct defect.

EXTRACTED CAPABILITY (CAP-030, CAP-031, CAP-042).

The register's job is to stop three different things being conflated in a
client deliverable, because conflating them is what makes a report untrustworthy:

  DEFECT      a confirmed weakness, reproduced, with evidence
  UNRESOLVED  accepted without error, but the impact is not provable from
              outside -- real but unproven, and it must not be counted as a
              confirmed defect
  CONTROL     a control that was attacked and held. A positive result, and
              worth reporting: it is the evidence that the assessment actually
              exercised the control rather than skipping it

Two rules are enforced in code rather than left to discipline:

  * Aggregates -- affected endpoints, occurrence counts, evidence paths -- are
    always DERIVED from run data. Hand-typing them is how a report ends up
    claiming four endpoints when three were tested.
  * A defect citing a case id that is not in the run data raises. A stale
    definition left over from a previous run would otherwise silently produce
    a finding with no evidence behind it.
"""
from ..core.errors import RegisterError
from ..oracle import verdict as V

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

KIND_DEFECT = "DEFECT"
KIND_UNRESOLVED = "UNRESOLVED"
KIND_CONTROL = "CONTROL"
KIND_SCOPE_EXCLUDED = "SCOPE-EXCLUDED"
KINDS = (KIND_DEFECT, KIND_UNRESOLVED, KIND_CONTROL, KIND_SCOPE_EXCLUDED)

PROV_AUTHORED = "AUTHORED"
PROV_MACHINE = "MACHINE"
PROV_BOTH = "AUTHORED+EVIDENCED"

#: How strongly a finding is established. ENGINEERING IMPROVEMENT (review
#: finding 4: "a rejected request does not necessarily prove a security
#: control worked, and an accepted request does not necessarily prove
#: exploitation").
#:
#: The register previously had one bucket for "we think this is real" --
#: DEFECT -- and the machine promoter filled it directly from a verdict. So a
#: single CONTROL-ABSENT row, which means no more than "the application
#: accepted input our case declared it should reject", was published as a
#: confirmed defect with an impact paragraph. Confidence is now a separate,
#: required axis:
#:
#:   SUSPECTED           an automated verdict or detector match, unreviewed.
#:                       Says what was observed; claims no impact.
#:   REPRODUCED          observed again, deliberately, with a working
#:                       baseline alongside it to show the harness was sound.
#:   MANUALLY_CONFIRMED  a human drove the exploitation path and saw the
#:                       consequence.
CONF_SUSPECTED = "suspected"
CONF_REPRODUCED = "reproduced"
CONF_MANUAL = "manually-confirmed"
CONFIDENCE = (CONF_SUSPECTED, CONF_REPRODUCED, CONF_MANUAL)

#: Confidence levels that may be published as a confirmed DEFECT. A suspected
#: finding is real work and belongs in the deliverable -- as UNRESOLVED, which
#: is the kind that exists precisely for "accepted without error, but the
#: impact is not provable from outside".
DEFECT_CONFIDENCE = (CONF_REPRODUCED, CONF_MANUAL)

#: What a DEFECT row must carry before a report citing it may be issued.
DEFECT_REQUIREMENTS = (
    ("expected_behaviour", "what a correctly implemented target must do"),
    ("observed_behaviour", "what this target actually did"),
    ("recommendation", "what the client should change"),
    ("alternative_explanations",
     "the other things that could produce this observation, and why they were "
     "ruled out"),
)


class Entry(object):
    """One register row."""

    def __init__(self, id, title, kind=KIND_DEFECT, severity="Medium",
                 category="", cwe="", description="", impact="",
                 recommendation="", case_ids=None, provenance=PROV_AUTHORED,
                 owasp="", notes="", poc=None, conclusion="",
                 confidence=CONF_SUSPECTED, expected_behaviour="",
                 observed_behaviour="", alternative_explanations=None,
                 limitations=None, state_verification="",
                 baseline_reference=""):
        if kind not in KINDS:
            raise RegisterError("entry %s: kind %r must be one of %s"
                                % (id, kind, KINDS))
        if severity not in SEVERITY_RANK:
            raise RegisterError("entry %s: unknown severity %r" % (id, severity))
        if confidence not in CONFIDENCE:
            raise RegisterError("entry %s: confidence %r must be one of %s"
                                % (id, confidence, CONFIDENCE))
        if kind == KIND_DEFECT and confidence not in DEFECT_CONFIDENCE:
            raise RegisterError(
                "entry %s is kind DEFECT with confidence %r. A defect is a "
                "weakness that was REPRODUCED or manually confirmed; an "
                "automated verdict on its own is %r and belongs in the "
                "register as %s, which is the kind for a real result whose "
                "impact is not provable from outside. Raising the confidence "
                "means doing the work, not editing the field."
                % (id, confidence, CONF_SUSPECTED, KIND_UNRESOLVED))
        self.id = id
        self.title = title
        self.kind = kind
        self.severity = severity
        self.category = category
        self.cwe = cwe
        self.description = description
        self.impact = impact
        self.recommendation = recommendation
        self.case_ids = list(case_ids or [])
        self.provenance = provenance
        self.owasp = owasp
        self.notes = notes
        self.poc = poc
        self.conclusion = conclusion
        self.confidence = confidence
        #: The declared contract and the observation, kept apart. Collapsing
        #: them into one "description" is how a report ends up asserting that
        #: the observation was the violation.
        self.expected_behaviour = expected_behaviour
        self.observed_behaviour = observed_behaviour
        #: What else could produce this observation. A finding with none
        #: listed has not been thought about, which is why an issuable DEFECT
        #: requires them.
        self.alternative_explanations = list(alternative_explanations or [])
        self.limitations = list(limitations or [])
        #: For a data-changing case: was the resulting state actually checked?
        self.state_verification = state_verification
        # Derived; populated by Register.build().
        self.baseline_reference = baseline_reference
        self.affected_endpoints = []
        self.endpoint_count = 0
        self.occurrences = 0
        self.evidence_files = []
        self.observed_layers = []
        self.observed_verdicts = []
        self.capture_methods = []

    @property
    def is_confirmed(self):
        return self.kind == KIND_DEFECT

    def issuable_problems(self):
        """What is missing before a report citing this row may be issued.

        Applied to DEFECT rows: those are the ones a client acts on, and the
        ones a dispute is about. An UNRESOLVED or CONTROL row is held to the
        lighter standard of saying what was expected and what was seen.
        """
        problems = []
        if self.kind == KIND_DEFECT:
            for field, what in DEFECT_REQUIREMENTS:
                if not getattr(self, field):
                    problems.append(
                        "finding %s is a DEFECT with no %s (%s)"
                        % (self.id, field, what))
            if not self.evidence_files:
                problems.append(
                    "finding %s is a DEFECT with no request/response evidence "
                    "attached" % self.id)
            if not self.baseline_reference:
                problems.append(
                    "finding %s is a DEFECT with no working baseline recorded; "
                    "without one, a rejection cannot be told apart from a "
                    "broken harness and an acceptance cannot be told apart "
                    "from a target that accepts everything" % self.id)
        elif self.kind in (KIND_UNRESOLVED, KIND_CONTROL):
            if not self.observed_behaviour:
                problems.append("finding %s does not state what was observed"
                                % self.id)
        return problems

    def as_dict(self):
        return {
            "id": self.id, "title": self.title, "kind": self.kind,
            "severity": self.severity, "category": self.category,
            "cwe": self.cwe, "description": self.description,
            "impact": self.impact, "recommendation": self.recommendation,
            "case_ids": self.case_ids, "provenance": self.provenance,
            "owasp": self.owasp, "notes": self.notes, "poc": self.poc,
            "conclusion": self.conclusion,
            "confidence": self.confidence,
            "expected_behaviour": self.expected_behaviour,
            "observed_behaviour": self.observed_behaviour,
            "alternative_explanations": self.alternative_explanations,
            "limitations": self.limitations,
            "state_verification": self.state_verification,
            "baseline_reference": self.baseline_reference,
            "affected_endpoints": self.affected_endpoints,
            "endpoint_count": self.endpoint_count,
            "occurrences": self.occurrences,
            "evidence_files": self.evidence_files,
            "observed_layers": self.observed_layers,
            "observed_verdicts": self.observed_verdicts,
            "capture_methods": self.capture_methods,
        }

    def __repr__(self):
        return "<Entry %s %s %s %r>" % (self.id, self.kind, self.severity,
                                        self.title[:40])


class Register(object):
    def __init__(self, entries=None, records=None, strict=True):
        self.entries = list(entries or [])
        self.records = list(records or [])
        self.strict = strict
        self._by_case = {r.get("case_id"): r for r in self.records}

    # -- construction ----------------------------------------------------
    def add(self, entry):
        if any(e.id == entry.id for e in self.entries):
            raise RegisterError("duplicate register entry id %r" % entry.id)
        self.entries.append(entry)
        return entry

    def build(self, max_evidence=3):
        """Derive every aggregate from the run records."""
        for entry in self.entries:
            unknown = [c for c in entry.case_ids if c not in self._by_case]
            if unknown:
                msg = ("register entry %s cites case id(s) absent from the run "
                       "data: %s. A stale definition would otherwise produce a "
                       "finding with no evidence behind it."
                       % (entry.id, ", ".join(unknown)))
                if self.strict:
                    raise RegisterError(msg)
                entry.notes = (entry.notes + " | " if entry.notes else "") + msg

            rows = [self._by_case[c] for c in entry.case_ids
                    if c in self._by_case]
            endpoints = sorted({r.get("endpoint") for r in rows
                                if r.get("endpoint")})
            entry.affected_endpoints = endpoints
            entry.endpoint_count = len(endpoints)
            entry.occurrences = len(rows)
            entry.observed_layers = sorted({r.get("layer") for r in rows
                                            if r.get("layer")})
            entry.observed_verdicts = sorted({r.get("verdict") for r in rows
                                              if r.get("verdict")})
            entry.capture_methods = sorted({r.get("capture_method")
                                            for r in rows
                                            if r.get("capture_method")})
            files = []
            for r in rows[:max_evidence]:
                if r.get("response_file"):
                    files.append(r["response_file"])
            entry.evidence_files = files

            if not entry.baseline_reference:
                entry.baseline_reference = self.baseline_for(endpoints)
            if not entry.state_verification:
                entry.state_verification = self.state_note(rows)

            if entry.case_ids and rows and entry.provenance == PROV_AUTHORED:
                entry.provenance = PROV_BOTH
        return self

    # -- derived context -------------------------------------------------
    def baseline_for(self, endpoints):
        """The working baseline that stands behind a finding on *endpoints*.

        ENGINEERING IMPROVEMENT (review finding 4: every finding should carry
        "a working baseline using the appropriate identity").

        The run already executes baselines and already refuses to call a run
        conclusive without them -- but the finding ROW did not cite one, so a
        reader of a single row could not tell whether the rejection it
        describes was the control working or the harness being broken. This
        pulls the relevant baseline into the row, with its identity and its
        verdict, and says so plainly when there is none.
        """
        from ..corpus.generators.retest import BASELINE_PREFIX
        wanted = set(endpoints or [])
        rows = [r for r in self.records
                if str(r.get("case_id", "")).startswith(BASELINE_PREFIX + "-")
                and (not wanted or r.get("endpoint") in wanted)]
        if not rows:
            return ""
        parts = []
        for row in sorted(rows, key=lambda r: str(r.get("case_id"))):
            parts.append("%s on %s as identity %s -> %s"
                         % (row.get("case_id"), row.get("endpoint"),
                            row.get("identity") or "default",
                            row.get("verdict")))
        return "; ".join(parts)

    def state_note(self, rows):
        """Whether the resulting state was checked, for data-changing cases.

        Silence is not evidence of no change. A case that mutated state and
        was never read back is reported as exactly that.
        """
        mutating = [r for r in rows if r.get("state_mutating")]
        if not mutating:
            return "no data-changing case supports this finding"
        verified = [r for r in mutating if r.get("state_verified")]
        if verified and len(verified) == len(mutating):
            return ("resulting state read back and confirmed for %d "
                    "data-changing case(s)" % len(verified))
        if verified:
            return ("resulting state read back for %d of %d data-changing "
                    "case(s); the remainder are unverified"
                    % (len(verified), len(mutating)))
        return ("NOT VERIFIED: %d data-changing case(s) support this finding "
                "and the resulting state was not read back, so whether the "
                "request actually changed anything is unestablished"
                % len(mutating))

    # -- machine promotion ----------------------------------------------
    def promote_machine_findings(self, prefix="M", min_severity="Low"):
        """Turn unexplained CONTROL-ABSENT results and detector hits into
        machine-provenance entries, grouped so one defect is one row.

        Grouped by (payload_class, layer) for verdict-driven findings and by
        detector rule id for disclosure findings -- otherwise a single defect
        affecting every endpoint produces dozens of near-identical rows, which
        is the inflation this register exists to prevent.

        ENGINEERING IMPROVEMENT (review finding 4). These were promoted as
        ``DEFECT`` with an authored-sounding impact paragraph. They are not
        defects yet: a CONTROL-ABSENT verdict means the application accepted
        input that a case declared it should reject, which is a finding worth
        reporting but is not proof of exploitation, and a detector match is a
        string in a response body, not a demonstrated consequence. They are
        now promoted as ``UNRESOLVED`` with confidence ``suspected``, each
        carrying the alternative explanations a reviewer has to rule out
        before raising it. Raising one to DEFECT is a human act that requires
        reproducing it -- which is the work the old behaviour skipped.
        """
        floor = SEVERITY_RANK[min_severity]
        claimed = {c for e in self.entries for c in e.case_ids}
        groups = {}

        for rec in self.records:
            cid = rec.get("case_id")
            if cid in claimed:
                continue
            for hit in rec.get("detector_hits") or []:
                key = ("detector", hit["rule_id"])
                groups.setdefault(key, {"rows": [], "hit": hit})["rows"].append(rec)
            if rec.get("verdict") == V.CONTROL_ABSENT:
                key = ("absent", rec.get("payload_class"), rec.get("layer"))
                groups.setdefault(key, {"rows": [], "hit": None})["rows"].append(rec)

        n = 0
        for key in sorted(groups, key=lambda k: str(k)):
            group = groups[key]
            rows = group["rows"]
            hit = group["hit"]
            if hit:
                severity = hit["severity"]
                title = hit["name"]
                category = "Information disclosure"
                cwe = hit.get("cwe", "")
                expected = ("The response should carry no internal "
                            "implementation detail: a client receives a "
                            "generic error and the detail is logged "
                            "server-side.")
                observed = ("A response body matched detector %s (%s). "
                            "Excerpt: %s"
                            % (hit["rule_id"], hit["name"], hit["excerpt"]))
                description = observed
                impact = ("IF the matched text is genuinely internal detail, "
                          "it assists an attacker in targeting the "
                          "underlying component. The impact of this instance "
                          "has not been demonstrated.")
                recommendation = ("Return a generic error to the client and "
                                  "log the detail server-side only.")
                alternatives = [
                    "the matched string is sample, placeholder or "
                    "documentation text rather than live internal detail",
                    "the detector pattern matched something structurally "
                    "similar but harmless (a false positive)",
                    "the detail is already public knowledge about a "
                    "component whose version is advertised deliberately",
                ]
            else:
                severities = [r.get("severity_if_accepted", "Low") for r in rows]
                severity = min(severities,
                               key=lambda s: SEVERITY_RANK.get(s, 99))
                pclass, layer = key[1], key[2]
                title = ("Input of class %r accepted where rejection was "
                         "required (%s)" % (pclass, layer))
                category = "Input validation"
                cwe = "CWE-20: Improper Input Validation"
                expected = ("Each of these cases declared, before execution, "
                            "that a correctly implemented target rejects the "
                            "input it carries.")
                observed = (
                    "%d case(s) of payload class %r were accepted rather than "
                    "rejected. Attribution layer: %s."
                    % (len(rows), pclass, layer))
                description = observed
                impact = ("IF the input is processed downstream as submitted, "
                          "the consequence depends on that handling. Nothing "
                          "downstream was observed, so no impact is claimed "
                          "here.")
                recommendation = ("Validate the affected fields against an "
                                  "explicit schema and fail closed on input "
                                  "that does not conform.")
                alternatives = [
                    "the input is rejected or neutralised later in "
                    "processing, where this assessment cannot observe it",
                    "the declared expectation is wrong for this endpoint -- "
                    "the API may legitimately accept this input",
                    "the acceptance was recorded against a request the target "
                    "did not actually act on (no resulting state was read "
                    "back)",
                ]
            if SEVERITY_RANK.get(severity, 99) > floor:
                continue
            n += 1
            self.add(Entry(
                "%s-%02d" % (prefix, n), title,
                # UNRESOLVED, not DEFECT: see the docstring. This is the
                # register's existing kind for a real-but-unproven result.
                kind=KIND_UNRESOLVED,
                confidence=CONF_SUSPECTED,
                severity=severity, category=category, cwe=cwe,
                description=description, impact=impact,
                expected_behaviour=expected, observed_behaviour=observed,
                alternative_explanations=alternatives,
                limitations=[
                    "produced automatically from run data; no human has "
                    "reproduced or confirmed it",
                    "promote it to DEFECT only after reproducing it "
                    "deliberately and recording the exploitation path",
                ],
                conclusion=("SUSPECTED. Reported because it was observed, not "
                            "because it was proven. Reproduce before "
                            "presenting it as a confirmed defect."),
                recommendation=recommendation,
                case_ids=[r.get("case_id") for r in rows],
                provenance=PROV_MACHINE,
                owasp=next(iter(sorted({r.get("owasp") for r in rows
                                        if r.get("owasp")})), "")))
        return self

    # -- headline evidence ----------------------------------------------
    #: How decisive a layer attribution is as evidence for a finding. A case
    #: the target ACCEPTED demonstrates a missing control far more directly
    #: than one it refused somewhere deep, so acceptance ranks first.
    DECISIVENESS = {
        "accepted_success": 0, "business_reached": 1, "business_reject": 2,
        "validation_reject": 3, "auth_reject": 4, "method_reject": 5,
        "ctype_reject": 6, "edge_reject": 7, "route_404": 8,
        "server_error": 9, "edge_block": 10, "transport_error": 11,
    }

    def headline_case(self, entry):
        """The single case that best evidences *entry*.

        EXTRACTED CAPABILITY (CAP-041). The source nominated these by hand,
        which does not scale and quietly degrades as a corpus grows. The
        deterministic rule is: prefer a case carrying a detector hit (direct
        evidence of the defect in the response), then the most decisive layer
        attribution, then the highest pre-declared severity, then the lowest
        case id so the choice is stable across runs.
        """
        rows = [self._by_case[c] for c in entry.case_ids
                if c in self._by_case]
        if not rows:
            return None

        def key(row):
            return (
                0 if row.get("detector_hits") else 1,
                self.DECISIVENESS.get(row.get("layer"), 99),
                SEVERITY_RANK.get(row.get("severity_if_accepted"), 99),
                str(row.get("case_id")),
            )

        return sorted(rows, key=key)[0]

    def headline_index(self):
        """One nominated case per entry, for PoC capture."""
        index = []
        for entry in self.sorted_entries():
            row = self.headline_case(entry)
            if row is None:
                continue
            index.append({
                "finding_id": entry.id, "title": entry.title,
                "severity": entry.severity, "case_id": row.get("case_id"),
                "layer": row.get("layer"), "verdict": row.get("verdict"),
                "capture_method": row.get("capture_method"),
                "request_file": row.get("request_file"),
                "response_file": row.get("response_file"),
                "has_detector_hit": bool(row.get("detector_hits")),
                "selection": "deterministic",
            })
        return index

    # -- queries ---------------------------------------------------------
    def sorted_entries(self):
        return sorted(self.entries,
                      key=lambda e: (KINDS.index(e.kind),
                                     SEVERITY_RANK[e.severity], e.id))

    def confirmed(self):
        return [e for e in self.entries if e.kind == KIND_DEFECT]

    def controls(self):
        return [e for e in self.entries if e.kind == KIND_CONTROL]

    def severity_counts(self, kind=KIND_DEFECT):
        counts = {s: 0 for s in SEVERITY_ORDER}
        for e in self.entries:
            if e.kind == kind:
                counts[e.severity] += 1
        return counts

    def headline(self):
        """Counts a summary may state. Confirmed defects only."""
        return {
            "confirmed_defects": len(self.confirmed()),
            "suspected": sum(1 for e in self.entries
                             if e.confidence == CONF_SUSPECTED),
            "reproduced": sum(1 for e in self.entries
                              if e.confidence == CONF_REPRODUCED),
            "manually_confirmed": sum(1 for e in self.entries
                                      if e.confidence == CONF_MANUAL),
            "unresolved": sum(1 for e in self.entries
                              if e.kind == KIND_UNRESOLVED),
            "scope_excluded": sum(1 for e in self.entries
                                  if e.kind == KIND_SCOPE_EXCLUDED),
            "verified_controls": len(self.controls()),
            "by_severity": self.severity_counts(),
        }

    def issuable_problems(self):
        """Every row's missing element, collected. Consumed by ReportModel."""
        problems = []
        for entry in self.sorted_entries():
            problems.extend(entry.issuable_problems())
        return problems

    def as_dict(self):
        return {
            "headline": self.headline(),
            "entries": [e.as_dict() for e in self.sorted_entries()],
        }
