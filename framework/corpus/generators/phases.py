"""Phase generators P1-P7.

EXTRACTED CAPABILITY (CAP-005). The source's deep corpus, generalised.

Where the families in ``families.py`` are organised by *payload shape*, these
are organised by *security question* and mapped to OWASP API classes. The two
are complementary: families give breadth of malformed input, phases give
depth against a specific control.

Ordering is a safety property. Phases run least-to-most state-mutating, so a
run can be stopped at any phase boundary and everything already executed will
have been the less invasive work. See ``methodology/phases.py``.
"""
import json

from ...methodology import phases as PH
from ...methodology import taxonomy as TX
from .. import payload as PL
from ..case import Case
from ..payload import PayloadTemplate


def _tpl(profile, endpoint_id):
    return PayloadTemplate(profile.template_for(endpoint_id), endpoint_id)


def _body(profile, endpoint_id, **overrides):
    tpl = _tpl(profile, endpoint_id)
    ep = profile.endpoint(endpoint_id)
    ident = profile.identifier_for(endpoint_id) if ep.get("identifier_space") else None
    spaces = profile.data.get("identifier_spaces") or {}
    corr = (profile.generate_identifier("correlation")
            if (tpl.correlation_path and "correlation" in spaces)
            else (PL.get(tpl.body, tpl.correlation_path)
                  if tpl.correlation_path else None))
    body = tpl.instantiate(identifier=ident, correlation=corr)
    for path, value in overrides.items():
        body = PL.set_(body, path, value)
    return tpl, body


def _mk(cid, phase, endpoint, expectation, desc, body, **kw):
    meta = PH.get(phase)
    kw.setdefault("state_mutating", meta["default_mutating"])
    kw.setdefault("owasp", meta["owasp"])
    return Case(cid, endpoint, expectation, desc, phase=phase,
                body=json.dumps(body) if body is not None else None, **kw)


# -- P1: function-level authorization ------------------------------------
def phase_1(profile, auth_provider):
    """Can an identity with the wrong role perform a privileged action?

    The requests are deliberately well formed. A malformed request that is
    refused proves nothing about authorization -- it may have died in
    validation. Only a perfectly valid request isolates the role check.
    """
    out = []
    wrong = auth_provider.identities_with_purpose("wrong_role")
    if not wrong:
        return out
    n = 0
    for identity in wrong:
        for ep in profile.endpoint_ids:
            n += 1
            tpl, body = _body(profile, ep)
            out.append(_mk("P1-%02d" % n, "P1", ep, "reject",
                           "Identity %r (insufficient role) submits a "
                           "well-formed request to %r" % (identity, ep),
                           body, identity=identity, payload_class="auth",
                           severity_if_accepted="High",
                           spec_reference="",
                           notes="request is valid in every respect except the "
                                 "caller's role, isolating the authorization "
                                 "check"))
        # The same identity attempting a negative state transition: some
        # services guard creation but not failure/cancellation paths.
        for ep in profile.endpoint_ids:
            tpl = _tpl(profile, ep)
            if not tpl.status_flag_path:
                continue
            n += 1
            _, body = _body(profile, ep)
            body = PL.set_(body, tpl.status_flag_path, False)
            if tpl.error_path:
                body = PL.set_(body, tpl.error_path, "SYNTH-DENIED")
            out.append(_mk("P1-%02d" % n, "P1", ep, "reject",
                           "Identity %r (insufficient role) attempts a FAILURE "
                           "state transition on %r" % (identity, ep),
                           body, identity=identity, payload_class="auth",
                           severity_if_accepted="High", state_mutating=True))
    return out


# -- P2: authentication --------------------------------------------------
def phase_2(profile, auth_provider):
    """Can an invalid, absent, mismatched or empty credential authenticate?"""
    out = []
    n = 0
    bad = auth_provider.identities_with_purpose("invalid_credential")
    primary = auth_provider.default_identity
    primary_headers = auth_provider.headers_for(primary)

    for identity in bad:
        for ep in profile.endpoint_ids:
            n += 1
            _, body = _body(profile, ep)
            out.append(_mk("P2-%02d" % n, "P2", ep, "reject",
                           "Identity %r (correct role, invalid credential) "
                           "submits a well-formed request to %r"
                           % (identity, ep),
                           body, identity=identity, payload_class="auth",
                           severity_if_accepted="High"))

    first = profile.endpoint_ids[0]

    # Credential rebinding: each credential individually valid, but belonging
    # to different subjects. A service that validates them independently rather
    # than as a bound pair accepts the combination.
    for identity in bad:
        other = auth_provider.headers_for(identity)
        shared = [k for k in primary_headers if k in other]
        if len(shared) >= 2:
            n += 1
            _, fresh = _body(profile, first)
            out.append(_mk("P2-%02d" % n, "P2", first, "reject",
                           "Credential %r from identity %r combined with %r "
                           "from %r (rebinding)"
                           % (shared[0], identity, shared[1], primary),
                           fresh, identity=primary,
                           header_overrides={shared[0]: other[shared[0]]},
                           payload_class="auth", severity_if_accepted="High",
                           notes="credentials must be validated as a bound set, "
                                 "not independently"))

    for name in primary_headers:
        n += 1
        _, fresh = _body(profile, first)
        out.append(_mk("P2-%02d" % n, "P2", first, "reject",
                       "Credential %r supplied empty while the remainder are "
                       "valid" % name, fresh,
                       header_overrides={name: ""}, payload_class="auth",
                       severity_if_accepted="High"))
    return out


# -- P3: object and identifier binding -----------------------------------
def phase_3(profile):
    """Are identifiers validated against each other and against entitlement?

    This phase found the highest-severity defect in the source engagement: a
    request carried both a resource identifier and a correlation identifier,
    and the two were never checked against one another.
    """
    out = []
    n = 0
    eps = [e for e in profile.endpoint_ids
           if profile.endpoint(e).get("identifier_space")]

    for ep in eps:
        tpl = _tpl(profile, ep)
        if not tpl.correlation_path:
            continue
        n += 1
        _, body = _body(profile, ep)
        foreign = profile.generate_identifier("correlation") \
            if "correlation" in (profile.data.get("identifier_spaces") or {}) \
            else "SYNTH-FOREIGN-CORRELATION"
        body = PL.set_(body, tpl.correlation_path, foreign)
        out.append(_mk("P3-%02d" % n, "P3", ep, "reject",
                       "Valid resource identifier on %r paired with a "
                       "correlation identifier belonging to a different "
                       "transaction" % ep, body,
                       payload_class="identifier", severity_if_accepted="High",
                       notes="the two identifiers must refer to the same "
                             "transaction"))

    # The same value used for both identifiers: they occupy different
    # namespaces, so one standing in for the other must be refused.
    for ep in eps:
        tpl = _tpl(profile, ep)
        if not tpl.correlation_path:
            continue
        n += 1
        _, body = _body(profile, ep)
        ident = PL.get(body, tpl.identifier_path)
        body = PL.set_(body, tpl.correlation_path, ident)
        out.append(_mk("P3-%02d" % n, "P3", ep, "reject",
                       "Resource identifier reused as the correlation "
                       "identifier on %r" % ep, body,
                       payload_class="identifier",
                       severity_if_accepted="Medium"))
        n += 1
        _, body2 = _body(profile, ep)
        corr = PL.get(body2, tpl.correlation_path)
        body2 = PL.set_(body2, tpl.identifier_path, corr)
        out.append(_mk("P3-%02d" % n, "P3", ep, "reject",
                       "Correlation identifier submitted in the resource "
                       "identifier field on %r" % ep, body2,
                       payload_class="identifier",
                       severity_if_accepted="Medium"))
    return out


# -- P4: business logic --------------------------------------------------
def phase_4(profile):
    """Can a caller assert a business outcome they should not control?"""
    out = []
    n = 0
    for ep in profile.endpoint_ids:
        tpl = _tpl(profile, ep)
        if not tpl.status_flag_path:
            continue
        n += 1
        _, body = _body(profile, ep)
        body = PL.set_(body, tpl.status_flag_path, False)
        if tpl.error_path:
            body = PL.set_(body, tpl.error_path, "SYNTH-REJECTED-BY-CALLER")
        out.append(_mk("P4-%02d" % n, "P4", ep, "observe",
                       "Force a FAILURE outcome on %r for a valid resource" % ep,
                       body, payload_class="structure",
                       severity_if_accepted="High", state_mutating=True,
                       notes="legitimate only if the caller is genuinely "
                             "entitled to report failure; must be attributable "
                             "and auditable either way"))
        n += 1
        _, body = _body(profile, ep)
        body = PL.set_(body, tpl.status_flag_path, True)
        if tpl.error_path:
            body = PL.set_(body, tpl.error_path, "SYNTH-REJECTED-BY-CALLER")
        out.append(_mk("P4-%02d" % n, "P4", ep, "reject",
                       "Assert SUCCESS on %r while the error field reports a "
                       "failure (contradictory state)" % ep, body,
                       payload_class="structure", severity_if_accepted="Medium",
                       state_mutating=True))
        if tpl.note_path:
            n += 1
            _, body = _body(profile, ep)
            body = PL.set_(body, tpl.note_path, "APPROVED")
            out.append(_mk("P4-%02d" % n, "P4", ep, "observe",
                           "Free-text note field set to an approval string on "
                           "%r" % ep, body, payload_class="structure",
                           severity_if_accepted="Medium", state_mutating=True,
                           notes="a descriptive field must not influence "
                                 "decisioning"))
    return out


# -- P5: mass assignment -------------------------------------------------
def phase_5(profile):
    """Do undeclared properties bind to domain objects?"""
    out = []
    n = 0
    for ep in profile.endpoint_ids:
        for label, extra, sev in TX.MASS_ASSIGNMENT_SETS:
            n += 1
            _, body = _body(profile, ep)
            if not isinstance(body, dict):
                continue
            merged = dict(body)
            merged.update(extra)
            out.append(_mk("P5-%02d" % n, "P5", ep, "reject",
                           "Undeclared %s injected into the %r payload"
                           % (label, ep), merged, payload_class="structure",
                           severity_if_accepted=sev, state_mutating=True,
                           notes="unknown properties must be rejected or "
                                 "ignored, never bound"))
    return out


# -- P6: breadth ---------------------------------------------------------
def phase_6(profile, core_only=True):
    """Apply the core payload families to every endpoint.

    Shared request-handling code means a defect found on one endpoint usually
    exists on all of them -- and a fix applied to only one endpoint is a
    common remediation failure. Breadth is what proves consistency either way.
    """
    from . import families as F
    out = []
    eps = profile.endpoint_ids
    letters = ["C", "D", "E"] if core_only else ["C", "D", "E", "F", "H", "I"]
    n = 0
    for letter in letters:
        fn = F.ALL_FAMILIES[letter]
        for case in fn(profile, endpoints=eps):
            n += 1
            case.id = "P6-%03d" % n
            case.phase = "P6"
            case.family = letter
            out.append(case)
    return out


# -- P7: surface and trust ----------------------------------------------
def phase_7(profile):
    """Does the service derive trust from client-controlled data?"""
    out = []
    n = 0
    first = profile.endpoint_ids[0]

    # Fresh body per case: a shared correlation identifier would be replayed
    # and refused by any target with idempotency protection.
    for name, value, sev in TX.METHOD_OVERRIDE_HEADERS:
        n += 1
        _, body = _body(profile, first)
        out.append(_mk("P7-%02d" % n, "P7", first, "reject",
                       "POST carrying %s: %s (verb tunnelling)" % (name, value),
                       body, header_overrides={name: value},
                       payload_class="method", severity_if_accepted=sev,
                       notes="the header must be ignored; no method "
                             "substitution"))

    for name, value, sev in TX.TRUST_HEADERS:
        n += 1
        _, body = _body(profile, first)
        kind = ("host override" if "host" in name.lower()
                else "source-address spoofing")
        out.append(_mk("P7-%02d" % n, "P7", first, "reject",
                       "%s set to %s (%s)" % (name, value, kind), body,
                       header_overrides={name: value},
                       payload_class="auth", severity_if_accepted=sev,
                       notes="trust must never derive from a client-supplied "
                             "header; substitute the address the target is "
                             "documented to trust via the engagement profile"))
    return out


PHASE_FUNCTIONS = {
    "P1": phase_1, "P2": phase_2, "P3": phase_3, "P4": phase_4,
    "P5": phase_5, "P6": phase_6, "P7": phase_7,
}

NEEDS_AUTH = ("P1", "P2")


def generate(profile, auth_provider=None, phase_ids=None, up_to=None):
    """Generate phases in execution order.

    *up_to* truncates at a phase boundary inclusive, which is how a run stops
    before the more invasive work.
    """
    if phase_ids:
        ordered = [p for p in PH.ORDERED_IDS if p in set(phase_ids)]
    else:
        ordered = [p["id"] for p in PH.ordered(up_to)]
    cases = []
    for pid in ordered:
        fn = PHASE_FUNCTIONS[pid]
        if pid in NEEDS_AUTH:
            if auth_provider is None:
                continue
            cases.extend(fn(profile, auth_provider))
        else:
            cases.extend(fn(profile))
    return cases
