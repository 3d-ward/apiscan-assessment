"""Scope enforcement.

EXTRACTED CAPABILITY (CAP-023, CAP-024) with its central weakness fixed.

The source encoded rules of engagement as a hand-maintained list of excluded
case *identifiers* in a separate file. That works until someone adds a case:
the new case has no entry, so it is not excluded, and a state-mutating or
volumetric request goes out without anyone deciding that it should. The list
and the corpus drift apart silently, and the failure mode is the dangerous
direction.

Here, scope matches on case *attributes* instead. A case declares what it does
-- whether it mutates state, what volume class it belongs to, what kind of
payload it carries -- and the policy denies classes. A newly added mutating case
is therefore denied by default without anyone needing to remember it.

Defaults fail safe: ``state_mutating`` defaults to true on a case, and
scope-excluded execution requires a recorded authorisation naming who approved
it, when, and against what reference.
"""
import datetime
import json
import os

from ..core.errors import AuthorisationError, ScopeViolation
from ..core.schema import ValidationError, validate

SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "configs", "schemas", "scope-policy.schema.json")

RISK_ORDER = ["read_only", "mutating", "volumetric", "destructive"]

#: Conservative default: refuse anything that changes state, generates volume,
#: or carries a payload that can itself damage a vulnerable target.
#:
#: ENGINEERING IMPROVEMENT (review finding: "make the default testing mode
#: genuinely conservative"). ``injection``, ``oversize`` and ``malformed`` were
#: previously permitted by default on the reasoning that they are annotated
#: non-mutating. That reasoning is wrong in the only case that matters: a
#: payload designed to exercise a missing control reaches the application
#: precisely when the control is missing, and an injection that succeeds, an
#: oversize body that exhausts a buffer or a malformed document that crashes a
#: parser changes state or availability whatever the annotation says. A case
#: cannot truthfully declare itself harmless against a target whose handling of
#: it is the unknown under test.
DEFAULT_DENY = ["state_mutating", "volumetric", "destructive",
                "infrastructure_pivot", "bulk_extraction",
                "injection", "oversize", "malformed"]

#: Classes that only an explicitly ACTIVE engagement mode may authorise. See
#: ``framework/governance/modes.py``.
AGGRESSIVE_CLASSES = frozenset(["volumetric", "destructive",
                                "infrastructure_pivot", "bulk_extraction",
                                "oversize", "injection"])

#: HTTP methods that write. A request using one of these is treated as
#: state-mutating whatever the case ANNOTATION says.
#:
#: ENGINEERING IMPROVEMENT (review finding: payloads "can still affect a
#: vulnerable application even when a case is labelled non-mutating"). The
#: annotation is an author's prediction about a target whose behaviour is the
#: unknown under test, and the generators set it to False for any case they
#: expect to be rejected -- 156 of the example corpus's POSTs, every one of
#: which creates a record if the validation it probes is missing. Deriving the
#: class from the method instead means the gate relies on something true by
#: HTTP semantics rather than on a prediction. A case may still declare itself
#: mutating when it uses a read method; the derivation only ever ADDS the
#: class.
WRITE_METHODS = frozenset(["POST", "PUT", "PATCH", "DELETE"])


class Authorisation(object):
    def __init__(self, spec):
        self.classes = set(spec["classes"])
        self.endpoints = set(spec.get("endpoints") or [])
        self.authorised_by = spec["authorised_by"]
        self.authorised_on = spec["authorised_on"]
        self.reference = spec["reference"]
        self.expires_on = spec.get("expires_on")
        self.note = spec.get("note", "")

    def is_expired(self, today=None):
        if not self.expires_on:
            return False
        today = today or datetime.date.today()
        try:
            exp = datetime.datetime.strptime(self.expires_on, "%Y-%m-%d").date()
        except ValueError:
            return True
        return today > exp

    def covers(self, klass, endpoint=None, today=None):
        if klass not in self.classes:
            return False
        if self.endpoints and endpoint and endpoint not in self.endpoints:
            return False
        return not self.is_expired(today)

    def describe(self):
        return "%s on %s (ref %s)" % (self.authorised_by, self.authorised_on,
                                      self.reference)


class Probe(object):
    """A non-corpus request, shaped so the scope gate can judge it.

    ENGINEERING IMPROVEMENT (review finding: "apply scope checks to every
    network request, including preflight and proxy probes").

    The gate used to see corpus cases only. Everything else that opened a
    socket -- the preflight reachability and oracle-calibration requests, the
    proxy forwarding and CA probes, the fidelity comparison, the rate-limit
    burst, the TLS handshakes -- reached the network without passing it. Those
    are requests to the client's infrastructure like any other, so they are
    given a case-shaped face here and judged by the same policy. One gate, no
    exceptions.

    Defaults fail closed. ``state_mutating`` is True, exactly as it is on a
    corpus case, so a probe whose author did not think about what it does is
    denied by the default policy rather than sent.
    """

    def __init__(self, probe_id, endpoint=None, method="",
                 state_mutating=True, volume_class="single",
                 payload_class="benign", risk_classes=None, use_proxy=None,
                 description=""):
        self.id = probe_id
        self.endpoint = endpoint
        #: Empty by default so a method allowlist written for HTTP cases does
        #: not accidentally deny a probe that issues no HTTP method.
        self.method = method
        self.state_mutating = bool(state_mutating)
        self.volume_class = volume_class
        self.payload_class = payload_class
        self.risk_classes = list(risk_classes or [])
        self.use_proxy = use_proxy
        self.description = description

    def __repr__(self):
        return "<%s %s>" % (type(self).__name__, self.id)


class TransportProbe(Probe):
    """A transport-layer probe: below HTTP, and direct by construction.

    ENGINEERING IMPROVEMENT. TLS and client-certificate probes open sockets to
    the target but are not corpus cases, so they never passed through
    ``filter``. Giving them a case-shaped face means one gate governs every
    packet the framework sends, instead of all-but-one.

    ``use_proxy`` is False by construction: a proxy that terminates TLS
    presents its own certificate, so transport evidence must be captured
    direct. That makes the probe visible to ``require_proxy`` rather than an
    unnoticed exception to it.
    """

    def __init__(self, probe_id, endpoint=None, risk_classes=None):
        super(TransportProbe, self).__init__(
            probe_id, endpoint=endpoint, method="", state_mutating=False,
            volume_class="single", payload_class="benign",
            risk_classes=list(risk_classes or []) + ["transport_probe"],
            use_proxy=False)


class ReadOnlyProbe(Probe):
    """A probe that is genuinely non-mutating: a GET, a handshake, a fetch.

    Declaring it explicitly is the point. A probe does not become read-only by
    being convenient to send; the author has to say so, and the class name is
    what a reviewer reads when asking why this request was permitted.
    """

    def __init__(self, probe_id, endpoint=None, method="GET",
                 risk_classes=None, use_proxy=None, description=""):
        super(ReadOnlyProbe, self).__init__(
            probe_id, endpoint=endpoint, method=method, state_mutating=False,
            risk_classes=list(risk_classes or []), use_proxy=use_proxy,
            description=description)


class ScopePolicy(object):
    def __init__(self, spec=None):
        spec = spec or {"schema": "scope-policy/1", "deny_classes": list(DEFAULT_DENY)}
        self.spec = spec
        self.deny_classes = set(spec.get("deny_classes") or [])
        self.allow_endpoints = set(spec.get("allow_endpoints") or [])
        self.deny_endpoints = set(spec.get("deny_endpoints") or [])
        self.allow_methods = set(m.upper() for m in (spec.get("allow_methods") or []))
        self.max_risk = spec.get("max_risk")
        #: Rules of engagement may require every request to traverse the
        #: intercepting proxy so the client has a reviewable record. Leaving
        #: the recorded path then needs an authorisation like any other
        #: denied class.
        self.require_proxy = bool(spec.get("require_proxy"))
        self.authorisations = [Authorisation(a)
                               for a in (spec.get("authorisations") or [])]
        #: Classes refused by the ENGAGEMENT MODE rather than by the policy.
        #: Checked before authorisations and never lifted by one: a cautious
        #: mode that an authorisation in the same engagement's policy file
        #: could override would not be a safety property, just a suggestion.
        self.hard_deny = set()
        self.mode_name = None

    def with_mode(self, mode):
        """Return a copy of this policy narrowed by an engagement mode.

        The policy records what the client agreed to; the mode records how
        much of it the operator is exercising now. Both must permit a request,
        and this is where the intersection is taken.
        """
        narrowed = ScopePolicy(self.spec)
        narrowed.hard_deny = set(getattr(mode, "hard_deny", ()) or ())
        narrowed.mode_name = getattr(mode, "name", str(mode))
        return narrowed

    # -- construction ----------------------------------------------------
    @classmethod
    def default(cls):
        return cls()

    @classmethod
    def load(cls, path):
        with open(path) as fh:
            spec = json.load(fh)
        with open(SCHEMA_PATH) as fh:
            schema = json.load(fh)
        try:
            validate(spec, schema)
        except ValidationError as exc:
            raise ScopeViolation("scope policy %s failed validation:\n%s"
                                 % (path, exc))
        return cls(spec)

    # -- evaluation ------------------------------------------------------
    def classes_of(self, case):
        """Attribute classes a case belongs to.

        ``state_mutating`` is the union of what the case declares and what its
        HTTP method implies. See WRITE_METHODS for why the declaration alone is
        not enough.
        """
        found = set()
        method = (getattr(case, "method", "") or "").upper()
        if getattr(case, "state_mutating", True) or method in WRITE_METHODS:
            found.add("state_mutating")
        volume = getattr(case, "volume_class", "single")
        if volume in ("burst", "sustained"):
            found.add("volumetric")
        payload = getattr(case, "payload_class", "benign")
        if payload in ("injection", "oversize", "malformed"):
            found.add(payload)
        for extra in (getattr(case, "risk_classes", None) or ()):
            found.add(extra)
        return found

    def risk_level(self, case):
        klasses = self.classes_of(case)
        if "destructive" in klasses:
            return "destructive"
        if "volumetric" in klasses:
            return "volumetric"
        if "state_mutating" in klasses:
            return "mutating"
        return "read_only"

    def transport_of(self, case, via_proxy=None):
        """Will this case traverse the proxy? ``None`` when the caller did not say.

        A case-level ``use_proxy`` overrides the run-level decision, which is
        precisely why it has to be visible to the gate.
        """
        case_level = getattr(case, "use_proxy", None)
        return case_level if case_level is not None else via_proxy

    def evaluate(self, case, today=None, via_proxy=None):
        """Return (permitted, reason). Never raises."""
        endpoint = getattr(case, "endpoint", None)
        method = (getattr(case, "method", "") or "").upper()

        # The engagement mode is checked first and cannot be authorised away.
        mode_denied = self.classes_of(case) & self.hard_deny
        if mode_denied:
            return False, (
                "class(es) %s are refused by engagement mode %r, which no "
                "authorisation overrides. Re-run in a mode that permits them "
                "if the engagement has agreed to them."
                % (", ".join(sorted(mode_denied)), self.mode_name or "?"))

        if self.deny_endpoints and endpoint in self.deny_endpoints:
            return False, "endpoint %r is explicitly out of scope" % endpoint
        if self.allow_endpoints and endpoint not in self.allow_endpoints:
            return False, ("endpoint %r is not in the authorised endpoint list"
                           % endpoint)
        if self.allow_methods and method and method not in self.allow_methods:
            return False, "method %s is not in the authorised method list" % method

        if self.require_proxy and self.transport_of(case, via_proxy) is False:
            auth = next((a for a in self.authorisations
                         if a.covers("direct_transport", endpoint, today)),
                        None)
            if auth is None:
                return False, (
                    "the scope policy requires every request to traverse the "
                    "proxy, and this case would be sent direct with no valid "
                    "authorisation for class 'direct_transport'")
            direct_note = "direct_transport authorised by %s" % auth.describe()
        else:
            direct_note = None

        if self.max_risk:
            level = self.risk_level(case)
            if RISK_ORDER.index(level) > RISK_ORDER.index(self.max_risk):
                return False, ("risk level %r exceeds the engagement ceiling %r"
                               % (level, self.max_risk))

        note = direct_note
        denied = self.classes_of(case) & self.deny_classes
        if not denied:
            return True, note or "within scope"

        derived_note = ""
        if ("state_mutating" in denied
                and not getattr(case, "state_mutating", True)):
            derived_note = (
                " (this case declares state_mutating=False, but it uses the "
                "write method %s, so the gate treats it as mutating: a "
                "request that creates a record when the validation it probes "
                "is missing is not non-mutating)"
                % ((getattr(case, "method", "") or "").upper()))

        uncovered = []
        covering = []
        for klass in sorted(denied):
            auth = next((a for a in self.authorisations
                         if a.covers(klass, endpoint, today)), None)
            if auth is None:
                uncovered.append(klass)
            else:
                covering.append("%s authorised by %s" % (klass, auth.describe()))
        if uncovered:
            return False, ("denied class(es) %s with no valid authorisation%s"
                           % (", ".join(uncovered), derived_note))
        if note:
            covering.append(note)
        return True, "; ".join(covering)

    def permits(self, case, today=None, via_proxy=None):
        return self.evaluate(case, today, via_proxy=via_proxy)[0]

    def filter(self, cases, today=None, via_proxy=None):
        """Split *cases* into (permitted, skipped) where skipped carries reasons."""
        permitted, skipped = [], []
        for case in cases:
            ok, reason = self.evaluate(case, today, via_proxy=via_proxy)
            (permitted if ok else skipped).append(
                case if ok else (case, reason))
        return permitted, skipped

    def require(self, case, today=None, via_proxy=None):
        ok, reason = self.evaluate(case, today, via_proxy=via_proxy)
        if not ok:
            raise AuthorisationError(
                "case %s is out of scope: %s. Record an authorisation in the "
                "engagement scope policy (classes, authorised_by, "
                "authorised_on, reference) before running it."
                % (getattr(case, "id", "?"), reason))
        return True
