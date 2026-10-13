"""Verifying what a request actually did, and who actually owns what.

ENGINEERING IMPROVEMENT (review finding 4, last two bullets):

    For data-changing tests, verify resulting state where feasible. For
    ownership checks, use controlled accounts and resources with known
    ownership.

Both are about the same failure: concluding something from a response alone.

**Resulting state.** A 200 to a create request is not proof that anything was
created, and a 400 is not proof that nothing was. Idempotency layers, queues,
soft deletes and write-behind caches all break the link between the status
code and the state. So where the API offers a read path -- declared per
endpoint as ``state_verification`` -- the framework reads the record back and
records what it found. Where it does not, the finding says NOT VERIFIED. The
second half is the half that matters: the previous behaviour was to say
nothing, which a reader takes as "no concern here".

**Ownership.** An object-level authorisation finding means "identity B
reached an object belonging to identity A". That requires knowing that the
object belongs to A. Incrementing an identifier until something comes back is
not that: it proves only that *an* object exists, it cannot distinguish a
missing control from a shared resource, and against a live system it risks
touching a real customer's data -- which is a worse outcome than an
unverified finding. So ownership cases are generated ONLY from resources the
engagement has declared, with the owning identity and the provenance of that
claim. With none declared, no cases are generated and the coverage statement
records object-level authorisation as not established.
"""
from ..case import Case
from ..payload import PayloadTemplate
from ..payload import get as pget

NOT_FEASIBLE = "not_feasible"
FEASIBLE = "feasible"


# -- resulting state -----------------------------------------------------
def state_verification_spec(profile, endpoint_id):
    """The declared read-back for an endpoint, or None."""
    endpoint = profile.endpoint(endpoint_id) or {}
    return endpoint.get("state_verification")


def feasibility(profile, endpoint_id):
    """(status, reason) -- can a change to this endpoint be read back?"""
    spec = state_verification_spec(profile, endpoint_id)
    if not spec:
        return NOT_FEASIBLE, (
            "endpoint %r declares no state_verification read path, so whether "
            "a request actually changed anything cannot be established from "
            "outside. Add one to the profile if the API offers a read "
            "endpoint; otherwise this is a real limit of external testing and "
            "belongs in the report's 'not established' list." % endpoint_id)
    read_endpoint = spec.get("read_endpoint")
    if read_endpoint not in profile.endpoint_ids:
        return NOT_FEASIBLE, (
            "endpoint %r names read_endpoint %r, which is not an endpoint id "
            "in this profile" % (endpoint_id, read_endpoint))
    return FEASIBLE, ("changes to %r can be read back via %r"
                      % (endpoint_id, read_endpoint))


def verification_case(profile, case, suffix="VERIFY"):
    """A read-back case for one data-changing case, or None.

    The returned case is non-mutating and declares ``expectation="observe"``:
    it is a measurement, not a test of a control, and must not contribute a
    pass or a fail to the tally.
    """
    status, _ = feasibility(profile, case.endpoint)
    if status != FEASIBLE:
        return None
    identifier = case.submitted_identifier
    if not identifier:
        return None
    spec = state_verification_spec(profile, case.endpoint)
    read_endpoint = spec["read_endpoint"]
    method = spec.get("method", "GET")
    where = spec.get("identifier_in", "query")

    header_overrides = {}
    body = None
    if where == "body":
        tpl = PayloadTemplate(profile.template_for(read_endpoint),
                              read_endpoint)
        path = spec.get("body_path") or tpl.identifier_path
        import json as _json
        from .. import payload as PL
        shape = PL.set_(tpl.instantiate(identifier=identifier,
                                        correlation=pget(tpl.body,
                                                         tpl.correlation_path)
                                        if tpl.correlation_path else None),
                        path, identifier)
        body = _json.dumps(shape)

    return Case(
        "%s-%s" % (suffix, case.id), read_endpoint, "observe",
        "State verification: read back the identifier submitted by %s to "
        "establish whether that request actually changed anything"
        % case.id,
        family="VERIFY", phase="VERIFY", method=method, body=body,
        header_overrides=header_overrides,
        identity=case.identity,
        payload_class="benign", severity_if_accepted="Informational",
        state_mutating=False, submitted_identifier=identifier,
        markers=list(spec.get("present_markers") or []),
        risk_classes=["state_verification"],
        notes=("Measures resulting state. Carries no verdict of its own: a "
               "read-back that finds nothing is evidence about %s, not about "
               "this endpoint." % case.id))


def interpret(spec, response_body):
    """What a read-back response says about existence. Never guesses.

    Returns one of "present", "absent" or "indeterminate". Indeterminate is a
    real answer and the common one when a profile declares no markers: the
    framework will not infer existence from a 200.
    """
    present = [m for m in (spec.get("present_markers") or []) if m]
    absent = [m for m in (spec.get("absent_markers") or []) if m]
    body = response_body or ""
    if present and any(m in body for m in present):
        return "present"
    if absent and any(m in body for m in absent):
        return "absent"
    if present:
        return "absent"
    return "indeterminate"


def plan_for(profile, cases):
    """Which data-changing cases can be verified, and which cannot.

    Produced before a run so the limitation is known in advance rather than
    discovered when the report is being written.
    """
    verifiable, unverifiable = [], []
    reasons = {}
    for case in cases:
        if not getattr(case, "state_mutating", True):
            continue
        status, reason = feasibility(profile, case.endpoint)
        if status == FEASIBLE and case.submitted_identifier:
            verifiable.append(case.id)
        else:
            unverifiable.append(case.id)
            reasons.setdefault(case.endpoint, reason)
    return {
        "data_changing_cases": len(verifiable) + len(unverifiable),
        "verifiable": verifiable,
        "unverifiable": unverifiable,
        "reasons_by_endpoint": reasons,
        "not_established": ([
            "the resulting state of %d data-changing case(s) was not read "
            "back, so whether those requests altered data is unestablished"
            % len(unverifiable)] if unverifiable else []),
    }


# -- ownership -----------------------------------------------------------
def controlled_resources(profile):
    return list((getattr(profile, "data", {}) or {}).get(
        "controlled_resources") or [])


def ownership_cases(profile, accessing_purpose="wrong_role"):
    """Object-level authorisation cases built from KNOWN ownership.

    Returns (cases, note). With no declared resources the case list is empty
    and the note is a limitation for the report -- never a silently skipped
    test, and never a guessed identifier.
    """
    declared = controlled_resources(profile)
    if not declared:
        return [], (
            "object-level authorisation was NOT TESTED: the profile declares "
            "no controlled_resources, so there is no object whose owner is "
            "known. Testing it by guessing identifiers would prove nothing "
            "about authorisation -- a response tells you an object exists, "
            "not whose it is -- and risks touching a real customer's record. "
            "Create a resource as one controlled identity, declare it with "
            "its owner and provenance, and re-run.")

    identity_names = set((profile.identities or {}).keys())
    accessor = None
    for name, spec in sorted((profile.identities or {}).items()):
        if spec.get("purpose") == accessing_purpose:
            accessor = name
            break
    if accessor is None:
        return [], (
            "object-level authorisation was NOT TESTED: the profile declares "
            "no identity with purpose %r to attempt the access as. An "
            "ownership test needs two controlled identities."
            % accessing_purpose)

    out = []
    problems = []
    for i, resource in enumerate(declared, 1):
        owner = resource.get("owned_by")
        endpoint = resource.get("endpoint")
        if owner not in identity_names:
            problems.append(
                "controlled resource %r claims owner %r, which is not a "
                "declared identity" % (resource.get("identifier"), owner))
            continue
        if endpoint not in profile.endpoint_ids:
            problems.append(
                "controlled resource %r names endpoint %r, which this profile "
                "does not declare" % (resource.get("identifier"), endpoint))
            continue
        if owner == accessor:
            problems.append(
                "controlled resource %r is owned by %r, which is also the "
                "accessing identity; that tests nothing"
                % (resource.get("identifier"), owner))
            continue
        if not resource.get("provenance"):
            problems.append(
                "controlled resource %r records no provenance for the "
                "ownership claim; a finding resting on it cannot be audited"
                % resource.get("identifier"))

        tpl = PayloadTemplate(profile.template_for(endpoint), endpoint)
        import json as _json
        from .. import payload as PL
        shape = PL.set_(tpl.instantiate(
            identifier=resource["identifier"],
            correlation=profile.generate_identifier("correlation")
            if "correlation" in (profile.data.get("identifier_spaces") or {})
            else None), tpl.identifier_path, resource["identifier"])

        out.append(Case(
            "OWN%02d" % i, endpoint, "reject",
            "Object-level authorisation: identity %r accesses a resource "
            "known to belong to identity %r (%s)"
            % (accessor, owner, resource.get("provenance", "provenance not "
                                             "recorded")),
            family="OWNERSHIP", phase="P4", method="POST",
            body=_json.dumps(shape), identity=accessor,
            payload_class="identifier", severity_if_accepted="High",
            state_mutating=True, owasp="API1:2023",
            submitted_identifier=resource["identifier"],
            risk_classes=["ownership_test"],
            notes=("Ownership is known, not inferred: %s. A rejection here is "
                   "evidence the control exists; an acceptance is evidence it "
                   "does not, and both are interpretable only because the "
                   "owner was established in advance."
                   % resource.get("provenance", "no provenance recorded"))))

    note = ("%d ownership case(s) built from declared controlled resources"
            % len(out))
    if problems:
        note += ". PROBLEMS: " + "; ".join(problems)
    return out, note
