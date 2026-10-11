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


class Entry(object):
    """One register row."""

    def __init__(self, id, title, kind=KIND_DEFECT, severity="Medium",
                 category="", cwe="", description="", impact="",
                 recommendation="", case_ids=None, provenance=PROV_AUTHORED,
                 owasp="", notes="", poc=None, conclusion=""):
        if kind not in KINDS:
            raise RegisterError("entry %s: kind %r must be one of %s"
                                % (id, kind, KINDS))
        if severity not in SEVERITY_RANK:
            raise RegisterError("entry %s: unknown severity %r" % (id, severity))
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
        # Derived; populated by Register.build().
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

    def as_dict(self):
        return {
            "id": self.id, "title": self.title, "kind": self.kind,
            "severity": self.severity, "category": self.category,
            "cwe": self.cwe, "description": self.description,
            "impact": self.impact, "recommendation": self.recommendation,
            "case_ids": self.case_ids, "provenance": self.provenance,
            "owasp": self.owasp, "notes": self.notes, "poc": self.poc,
            "conclusion": self.conclusion,
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

            if entry.case_ids and rows and entry.provenance == PROV_AUTHORED:
                entry.provenance = PROV_BOTH
        return self

    # -- machine promotion ----------------------------------------------
    def promote_machine_findings(self, prefix="M", min_severity="Low"):
        """Turn unexplained CONTROL-ABSENT results and detector hits into
        machine-provenance entries, grouped so one defect is one row.

        Grouped by (payload_class, layer) for verdict-driven findings and by
        detector rule id for disclosure findings -- otherwise a single defect
        affecting every endpoint produces dozens of near-identical rows, which
        is the inflation this register exists to prevent.
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
                description = (
                    "A response matched detector %s (%s). Excerpt: %s"
                    % (hit["rule_id"], hit["name"], hit["excerpt"]))
                impact = ("Internal implementation detail is exposed to a "
                          "caller, assisting an attacker in targeting the "
                          "underlying component.")
                recommendation = ("Return a generic error to the client and "
                                  "log the detail server-side only.")
            else:
                severities = [r.get("severity_if_accepted", "Low") for r in rows]
                severity = min(severities,
                               key=lambda s: SEVERITY_RANK.get(s, 99))
                pclass, layer = key[1], key[2]
                title = ("Input of class %r accepted where rejection was "
                         "required (%s)" % (pclass, layer))
                category = "Input validation"
                cwe = "CWE-20: Improper Input Validation"
                description = (
                    "%d case(s) of payload class %r were accepted; the "
                    "declared expectation for each was rejection. Attribution "
                    "layer: %s." % (len(rows), pclass, layer))
                impact = ("The absence of this control allows a caller to "
                          "submit input the service is not designed to "
                          "process, with consequences depending on downstream "
                          "handling.")
                recommendation = ("Validate the affected fields against an "
                                  "explicit schema and fail closed on input "
                                  "that does not conform.")
            if SEVERITY_RANK.get(severity, 99) > floor:
                continue
            n += 1
            self.add(Entry(
                "%s-%02d" % (prefix, n), title, kind=KIND_DEFECT,
                severity=severity, category=category, cwe=cwe,
                description=description, impact=impact,
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
            "unresolved": sum(1 for e in self.entries
                              if e.kind == KIND_UNRESOLVED),
            "scope_excluded": sum(1 for e in self.entries
                                  if e.kind == KIND_SCOPE_EXCLUDED),
            "verified_controls": len(self.controls()),
            "by_severity": self.severity_counts(),
        }

    def as_dict(self):
        return {
            "headline": self.headline(),
            "entries": [e.as_dict() for e in self.sorted_entries()],
        }
