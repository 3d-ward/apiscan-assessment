"""The unit of assessment: one case.

A case is a complete, self-describing test: what to send, where, as whom, what
a correctly implemented target must do, how risky it is, and why it exists.
Everything downstream -- scope filtering, execution, attribution, verdicts,
reporting, coverage -- reads these fields, so they are defined once here.

Design notes carried from the source, and the two defaults that were changed:

  * ``expectation`` is the contract a correct implementation must meet, declared
    before the result is known. Declaring it afterwards is how an assessment
    rationalises whatever it observed.
  * ``severity_if_accepted`` is likewise pre-declared.
  * ``state_mutating`` defaults to **True** (the source defaulted it False).
    An un-annotated case is assumed dangerous, so forgetting to annotate fails
    closed rather than sending an unreviewed mutating request.
  * ``spec_reference`` cites the clause of the engagement's own API
    documentation that motivates the case. It is free text supplied by the
    engagement: the framework never embeds a client specification.
"""
import json

EXPECTATIONS = ("reject", "accept", "observe")
VOLUME_CLASSES = ("single", "burst", "sustained")
PAYLOAD_CLASSES = ("benign", "injection", "oversize", "malformed", "structure",
                   "auth", "method", "media_type", "identifier")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")


class Case(object):
    __slots__ = ("id", "family", "phase", "endpoint", "method", "content_type",
                 "header_overrides", "body", "expectation", "description",
                 "severity_if_accepted", "state_mutating", "volume_class",
                 "payload_class", "identity", "finding_id", "spec_reference",
                 "owasp", "markers", "risk_classes", "shallow_reject_required",
                 "submitted_identifier", "use_proxy", "notes")

    def __init__(self, id, endpoint, expectation, description,
                 family="", phase="", method="POST",
                 content_type="application/json", header_overrides=None,
                 body=None, severity_if_accepted="Medium",
                 state_mutating=True, volume_class="single",
                 payload_class="benign", identity=None, finding_id=None,
                 spec_reference="", owasp="", markers=None, risk_classes=None,
                 shallow_reject_required=False, submitted_identifier=None,
                 use_proxy=None, notes=""):
        if expectation not in EXPECTATIONS:
            raise ValueError("case %s: expectation must be one of %s, got %r"
                             % (id, EXPECTATIONS, expectation))
        if volume_class not in VOLUME_CLASSES:
            raise ValueError("case %s: unknown volume_class %r" % (id, volume_class))
        if payload_class not in PAYLOAD_CLASSES:
            raise ValueError("case %s: unknown payload_class %r"
                             % (id, payload_class))
        if severity_if_accepted not in SEVERITIES:
            raise ValueError("case %s: unknown severity %r"
                             % (id, severity_if_accepted))
        self.id = id
        self.endpoint = endpoint
        self.expectation = expectation
        self.description = description
        self.family = family
        self.phase = phase
        self.method = method
        self.content_type = content_type
        self.header_overrides = dict(header_overrides or {})
        self.body = body
        self.severity_if_accepted = severity_if_accepted
        self.state_mutating = bool(state_mutating)
        self.volume_class = volume_class
        self.payload_class = payload_class
        self.identity = identity
        self.finding_id = finding_id
        self.spec_reference = spec_reference
        self.owasp = owasp
        self.markers = list(markers or [])
        self.risk_classes = list(risk_classes or [])
        self.shallow_reject_required = bool(shallow_reject_required)
        self.submitted_identifier = submitted_identifier
        self.use_proxy = use_proxy
        self.notes = notes

    def as_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}

    def __repr__(self):
        return "<Case %s %s %s %s>" % (self.id, self.phase or self.family,
                                       self.endpoint, self.expectation)


class Corpus(object):
    """An ordered, validated collection of cases."""

    def __init__(self, cases=None, name="corpus"):
        self.name = name
        self.cases = list(cases or [])
        self.validate()

    def validate(self):
        from ..core.errors import CorpusError
        seen = {}
        for c in self.cases:
            if c.id in seen:
                raise CorpusError("duplicate case id %r" % c.id)
            seen[c.id] = True
        return True

    def add(self, case):
        self.cases.append(case)
        return case

    def extend(self, cases):
        self.cases.extend(cases)
        self.validate()
        return self

    def __len__(self):
        return len(self.cases)

    def __iter__(self):
        return iter(self.cases)

    def select(self, ids=None, endpoint=None, phase=None, family=None,
               finding_id=None, payload_class=None):
        out = list(self.cases)
        if ids:
            want = {i.strip().upper() for i in ids}
            out = [c for c in out if c.id.upper() in want]
        if endpoint:
            out = [c for c in out if c.endpoint == endpoint]
        if phase:
            out = [c for c in out if c.phase == phase]
        if family:
            out = [c for c in out if c.family == family]
        if finding_id:
            out = [c for c in out if c.finding_id == finding_id]
        if payload_class:
            out = [c for c in out if c.payload_class == payload_class]
        return out

    def counts(self, attr):
        out = {}
        for c in self.cases:
            key = getattr(c, attr, None) or "(unset)"
            out[key] = out.get(key, 0) + 1
        return out

    def coverage_matrix(self, row="phase", col="endpoint"):
        """Sparse matrix of case counts -- the input to gap detection."""
        matrix = {}
        for c in self.cases:
            r, cl = getattr(c, row, None), getattr(c, col, None)
            matrix.setdefault(r, {}).setdefault(cl, 0)
            matrix[r][cl] += 1
        return matrix

    def to_json(self, indent=1):
        return json.dumps([c.as_dict() for c in self.cases], indent=indent,
                          default=str)

    @classmethod
    def from_json(cls, text, name="corpus"):
        data = json.loads(text)
        return cls([Case(**{k: v for k, v in rec.items()
                            if k in Case.__slots__}) for rec in data], name)


def find_gaps(corpus, rows, cols, row_attr="phase", col_attr="endpoint"):
    """Cells with no coverage.

    EXTRACTED CAPABILITY (CAP-028), mechanised. The source completed a coverage
    matrix by hand after noticing the gap during review; computing it means the
    gap is reported rather than noticed.
    """
    matrix = corpus.coverage_matrix(row_attr, col_attr)
    gaps = []
    for r in rows:
        for c in cols:
            if matrix.get(r, {}).get(c, 0) == 0:
                gaps.append((r, c))
    return gaps
