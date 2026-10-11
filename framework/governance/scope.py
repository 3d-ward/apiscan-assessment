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

#: Conservative default: refuse anything that changes state or generates
#: volume until an engagement explicitly authorises it.
DEFAULT_DENY = ["state_mutating", "volumetric", "destructive",
                "infrastructure_pivot", "bulk_extraction"]


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


class TransportProbe(object):
    """A transport-layer probe, shaped so the scope gate can judge it.

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
        self.id = probe_id
        self.endpoint = endpoint
        #: Empty so a method allowlist written for HTTP cases does not
        #: accidentally deny a probe that issues no HTTP method.
        self.method = ""
        self.state_mutating = False
        self.volume_class = "single"
        self.payload_class = "benign"
        self.risk_classes = list(risk_classes or []) + ["transport_probe"]
        self.use_proxy = False

    def __repr__(self):
        return "<TransportProbe %s>" % self.id


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
        """Attribute classes a case belongs to."""
        found = set()
        if getattr(case, "state_mutating", True):
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
            return False, ("denied class(es) %s with no valid authorisation"
                           % ", ".join(uncovered))
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
