"""Second-order follow-up probes.

EXTRACTED CAPABILITY (CAP-029), generalised into a reusable library.

These are the questions a first run *raises* rather than answers. In the source
each was hand-written for one engagement; each is in fact a general technique,
and together they are among the most transferable things in the whole toolkit.
Every one exists because an obvious-looking result turned out to be incomplete:

  case_sensitivity    A uniqueness or equality check that is case-sensitive can
                      be bypassed by re-casing the value. "Duplicate rejected"
                      does not mean "duplicate detection works".
  scope_of_fix        A sanitisation fix is often applied to the one field named
                      in the report. Probing each field independently shows
                      whether the fix is general or local.
  cross_endpoint      Is a uniqueness constraint global or per-endpoint? A value
                      consumed on one endpoint may be replayable on another.
  per_node            A limit enforced by an edge component may only be
                      configured on the node that answered. Repeating the probe
                      samples a load-balanced pool.
  credential_lifecycle Is a credential issued long ago still accepted, and does
                      anything signal expiry?
  response_headers    Which security headers are present, and which discouraged
                      ones advertise the stack.
  method_and_media    Do unsupported methods and media types return the correct
                      status on *every* endpoint, not just the one tested?
"""
import json

from ...methodology import taxonomy as TX
from .. import payload as PL
from ..case import Case
from ..payload import PayloadTemplate


def _tpl(profile, endpoint_id):
    return PayloadTemplate(profile.template_for(endpoint_id), endpoint_id)


def _wellformed(profile, endpoint_id):
    tpl = _tpl(profile, endpoint_id)
    ep = profile.endpoint(endpoint_id)
    ident = profile.identifier_for(endpoint_id) if ep.get("identifier_space") else None
    spaces = profile.data.get("identifier_spaces") or {}
    corr = (profile.generate_identifier("correlation")
            if (tpl.correlation_path and "correlation" in spaces)
            else (PL.get(tpl.body, tpl.correlation_path)
                  if tpl.correlation_path else None))
    return tpl, tpl.instantiate(identifier=ident, correlation=corr)


def _mk(cid, endpoint, expectation, desc, body, probe, **kw):
    kw.setdefault("state_mutating", True)
    # A caller may supply richer notes; prefix the probe name rather than
    # colliding with the keyword.
    note = kw.pop("notes", "")
    kw["notes"] = ("follow-up probe: %s" % probe) + ((". " + note) if note
                                                     else "")
    return Case(cid, endpoint, expectation, desc, family="FOLLOWUP",
                phase="FOLLOWUP",
                body=json.dumps(body) if not isinstance(body, str) else body,
                **kw)


# -- 1. case sensitivity of a uniqueness check ---------------------------
def case_sensitivity(profile, consumed_value, endpoint=None, path=None):
    """Replay a consumed value re-cased.

    A control in place for the exact value but absent for its uppercase form
    is not a working uniqueness check.
    """
    ep = endpoint or profile.endpoint_ids[0]
    tpl, body = _wellformed(profile, ep)
    target = path or tpl.correlation_path
    if not target or not consumed_value:
        return []
    variants = [
        ("control-lower", consumed_value,
         "control: the consumed value exactly as first submitted"),
        ("upper", consumed_value.upper(),
         "same value uppercased -- succeeds if the check is case-sensitive"),
        ("mixed", "".join(ch.upper() if i % 2 else ch.lower()
                          for i, ch in enumerate(consumed_value)),
         "same value in mixed case"),
    ]
    out = []
    for suffix, value, why in variants:
        out.append(_mk("FU-CASE-%s" % suffix, ep, "reject",
                       "Replay of a consumed value, %s" % why,
                       PL.set_(body, target, value), "case_sensitivity",
                       payload_class="identifier",
                       severity_if_accepted="High"))
    return out


# -- 2. scope of a sanitisation fix --------------------------------------
def scope_of_fix(profile, vector, endpoint=None, paths=None, label="payload"):
    """Send the same vector into every writable field in turn.

    A filter applied to one named field leaves the others exposed; this is the
    most common shape of an incomplete remediation.
    """
    ep = endpoint or profile.endpoint_ids[0]
    tpl, body = _wellformed(profile, ep)
    targets = paths or [p for p in (tpl.mutable_paths or tpl.declared_paths())]
    out = []
    for i, path in enumerate(targets, 1):
        out.append(_mk("FU-SCOPE-%02d" % i, ep, "reject",
                       "%s vector submitted in field %r (probing whether the "
                       "filter covers this field or only the one reported)"
                       % (label, path),
                       PL.set_(body, path, vector), "scope_of_fix",
                       payload_class="injection", severity_if_accepted="Medium",
                       state_mutating=False))
    return out


# -- 3. cross-endpoint uniqueness ----------------------------------------
def cross_endpoint_uniqueness(profile, consumed_value, origin_endpoint=None):
    """Replay a value consumed on one endpoint against all the others."""
    origin = origin_endpoint or profile.endpoint_ids[0]
    out = []
    for i, ep in enumerate([e for e in profile.endpoint_ids if e != origin], 1):
        tpl, body = _wellformed(profile, ep)
        if not tpl.correlation_path:
            continue
        out.append(_mk("FU-XEP-%02d" % i, ep, "reject",
                       "Value consumed on %r replayed on %r (is uniqueness "
                       "global or per-endpoint?)" % (origin, ep),
                       PL.set_(body, tpl.correlation_path, consumed_value),
                       "cross_endpoint", payload_class="identifier",
                       severity_if_accepted="High"))
    return out


# -- 4. per-node consistency ---------------------------------------------
def per_node_consistency(profile, endpoint=None, repeats=10, size=20000):
    """Repeat an edge-limit probe to sample a load-balanced pool.

    A limit configured on only one node of a pool passes a single probe
    whenever that probe happens to land on the configured node.
    """
    ep = endpoint or profile.endpoint_ids[0]
    tpl, body = _wellformed(profile, ep)
    pad_path = tpl.note_path or tpl.identifier_path
    out = []
    for i in range(repeats):
        out.append(_mk("FU-NODE-%02d" % i, ep, "reject",
                       "Oversized body iteration %d of %d (sampling whether "
                       "every backend node enforces the limit)"
                       % (i + 1, repeats),
                       PL.set_(body, pad_path, "P" * size), "per_node",
                       payload_class="oversize", severity_if_accepted="Medium",
                       state_mutating=False, risk_classes=["volumetric"]))
    return out


# -- 5. credential lifecycle ---------------------------------------------
def credential_lifecycle(profile, endpoint=None, identity=None):
    """Is a long-lived credential still accepted, and is expiry signalled?

    Observes only. Lifetime, rotation and revocation are policy properties that
    cannot be proven from outside, so this probe establishes the one externally
    visible fact -- the credential still authenticates -- and the report must
    say that this does not close a lifecycle finding.
    """
    ep = endpoint or profile.endpoint_ids[0]
    _, body = _wellformed(profile, ep)
    return [_mk("FU-CRED-01", ep, "observe",
                "Existing credential presented to %r to establish whether it "
                "is still accepted and whether any expiry is signalled" % ep,
                body, "credential_lifecycle", identity=identity,
                payload_class="auth", severity_if_accepted="Medium",
                notes="Acceptance here evidences only that the credential is "
                      "still valid. Maximum lifetime, documented rotation and "
                      "emergency revocation are NOT observable from the client "
                      "side and must not be reported as verified.")]


# -- 6. response security headers ---------------------------------------
def response_headers(profile, endpoint=None):
    ep = endpoint or profile.endpoint_ids[0]
    _, body = _wellformed(profile, ep)
    return [_mk("FU-HDR-01", ep, "observe",
                "Well-formed request to %r for the sole purpose of inspecting "
                "response security headers" % ep, body, "response_headers",
                payload_class="benign", severity_if_accepted="Informational")]


def assess_response_headers(headers_text):
    """Evaluate observed headers against the expected/discouraged sets."""
    present = {}
    for line in (headers_text or "").splitlines():
        if ":" in line:
            name, _, value = line.partition(":")
            present[name.strip().lower()] = value.strip()
    missing, advertised = [], []
    for name, severity, why in TX.EXPECTED_SECURITY_HEADERS:
        if name.lower() not in present:
            missing.append({"header": name, "severity": severity, "why": why})
    for name, severity, why in TX.DISCOURAGED_RESPONSE_HEADERS:
        if name.lower() in present:
            advertised.append({"header": name, "severity": severity,
                               "why": why, "value": present[name.lower()]})
    return {"present": present, "missing": missing, "advertised": advertised}


# -- 7. method and media type across every endpoint ----------------------
def method_and_media(profile):
    """Confirm method and media-type handling is consistent everywhere."""
    out = []
    n = 0
    for ep in profile.endpoint_ids:
        declared = [m.upper() for m in (profile.endpoint(ep).get("methods")
                                        or ["POST"])]
        _, body = _wellformed(profile, ep)
        for method, sev in TX.UNEXPECTED_METHODS[:3]:
            if method in declared:
                continue
            n += 1
            out.append(Case("FU-MM-%02d" % n, ep, "reject",
                            "%s on %r (consistency across every endpoint)"
                            % (method, ep), family="FOLLOWUP", phase="FOLLOWUP",
                            body=json.dumps(body), method=method,
                            payload_class="method", severity_if_accepted=sev,
                            state_mutating=(method in ("DELETE", "PUT")),
                            notes="follow-up probe: method_and_media"))
        n += 1
        out.append(Case("FU-MM-%02d" % n, ep, "reject",
                        "Unsupported media type on %r (consistency across "
                        "every endpoint)" % ep, family="FOLLOWUP",
                        phase="FOLLOWUP", body=json.dumps(body),
                        content_type="text/plain", payload_class="media_type",
                        severity_if_accepted="Low", state_mutating=False,
                        notes="follow-up probe: method_and_media"))
    return out


PROBES = {
    "case_sensitivity": case_sensitivity,
    "scope_of_fix": scope_of_fix,
    "cross_endpoint": cross_endpoint_uniqueness,
    "per_node": per_node_consistency,
    "credential_lifecycle": credential_lifecycle,
    "response_headers": response_headers,
    "method_and_media": method_and_media,
}


def available():
    return sorted(PROBES)
