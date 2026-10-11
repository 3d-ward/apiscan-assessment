"""Expectation x layer -> verdict.

EXTRACTED CAPABILITY (CAP-007). A case declares what a correctly implemented
target must do; attribution says what it actually did; this maps the pair to a
statement about whether a security control is present.

Verdicts:
  CONTROL-PRESENT   the declared expectation was met
  CONTROL-ABSENT    the expectation was not met -- a control is missing
  OVER-BLOCKED      a legitimate request was refused (a functional defect, and
                    a signal the negative results may be unreliable)
  BLOCKED           stopped before the application; NOT a pass, NOT a failure
  ERROR             the target errored or no response was observed
  OBSERVED          no pass/fail declared; judged by detectors or by hand
  UNCLEAR           the outcome does not map to a verdict and needs review

Two policies are available.

``layered`` (default, ENGINEERING IMPROVEMENT)
    A refusal at *any* layer satisfies an expectation of rejection, and the
    layer is recorded alongside the verdict as ``control_depth``.

    Why this differs from the source: the original treated a business-layer
    refusal as a *failure* of the control, because the finding under test was
    usually "validation should reject this before business logic". That is right
    for a validation finding and wrong for a replay or idempotency finding,
    where a business-layer refusal ("already processed") IS the control working.
    In the source project this showed up as the automated verdict disagreeing
    with the assessor's authored verdict, which a human then adjudicated by
    hand. Recording depth instead of conflating it keeps both facts: the control
    exists, and it sits deeper than ideal.

``validation_strict`` (source-equivalent)
    Only a pre-business refusal counts as the control being present; a
    business-layer refusal is CONTROL-ABSENT. Retained so the original
    behaviour is reproducible and so regression tests can prove the
    reconstruction did not drift accidentally.

A case may set ``shallow_reject_required`` to demand a pre-business refusal
under the ``layered`` policy -- the correct way to express a validation finding
without changing global semantics.
"""
from . import layers as L

CONTROL_PRESENT = "CONTROL-PRESENT"
CONTROL_ABSENT = "CONTROL-ABSENT"
OVER_BLOCKED = "OVER-BLOCKED"
BLOCKED = "BLOCKED"
ERROR = "ERROR"
OBSERVED = "OBSERVED"
UNCLEAR = "UNCLEAR"

ALL = (CONTROL_PRESENT, CONTROL_ABSENT, OVER_BLOCKED, BLOCKED, ERROR,
       OBSERVED, UNCLEAR)

# Refusals that happen before application/business logic runs.
PRE_BUSINESS_REJECTS = frozenset([
    "edge_reject", "auth_reject", "method_reject", "ctype_reject",
    "validation_reject",
])

POLICIES = ("layered", "validation_strict")


class Decision(object):
    def __init__(self, verdict, layer, reason, control_depth=None):
        self.verdict = verdict
        self.layer = layer
        self.reason = reason
        self.control_depth = control_depth

    def __repr__(self):
        return "<Decision %s layer=%s depth=%s>" % (
            self.verdict, self.layer, self.control_depth)


def _depth(layer):
    if layer in PRE_BUSINESS_REJECTS:
        return "pre-business"
    if layer == "business_reject":
        return "business"
    return None


def decide(expectation, attribution, policy="layered",
           shallow_reject_required=False):
    """Map an expectation and an attribution to a Decision.

    *expectation* is "reject", "accept" or "observe".
    """
    if policy not in POLICIES:
        raise ValueError("unknown verdict policy %r (known: %s)"
                         % (policy, ", ".join(POLICIES)))

    layer = attribution.layer

    # Blocked and error outcomes are terminal regardless of expectation: an
    # unreached test is not evidence about the control it was meant to probe.
    if attribution.is_blocked:
        return Decision(BLOCKED, layer,
                        "stopped at a pre-application control (%s); the case "
                        "was not executed against the application"
                        % (attribution.remark or "edge block"))
    if attribution.is_error:
        return Decision(ERROR, layer,
                        "target error or no response (%s)"
                        % (attribution.remark or layer))

    if expectation == "observe":
        return Decision(OBSERVED, layer,
                        "no pass/fail declared; judged by detectors",
                        _depth(layer))

    if expectation == "reject":
        if layer in PRE_BUSINESS_REJECTS:
            return Decision(CONTROL_PRESENT, layer,
                            "refused at %s, before business logic" % layer,
                            "pre-business")
        if layer == "business_reject":
            if policy == "validation_strict" or shallow_reject_required:
                return Decision(
                    CONTROL_ABSENT, layer,
                    "reached business logic before being refused; a "
                    "pre-business control was required", "business")
            return Decision(CONTROL_PRESENT, layer,
                            "refused at business layer; the control exists but "
                            "sits deeper than a validation boundary", "business")
        if layer in L.REACHED_LAYERS:
            return Decision(CONTROL_ABSENT, layer,
                            "accepted where rejection was required")
        if layer == "route_404":
            return Decision(UNCLEAR, layer,
                            "404 with no business signal -- route may not exist; "
                            "verify the endpoint path before drawing a conclusion")
        return Decision(UNCLEAR, layer, "outcome %r does not map to a verdict"
                        % layer)

    if expectation == "accept":
        if layer == "accepted_success":
            return Decision(CONTROL_PRESENT, layer,
                            "accepted as expected", _depth(layer))
        if layer == "business_reached":
            return Decision(CONTROL_PRESENT, layer,
                            "reached business logic as expected", _depth(layer))
        if layer in PRE_BUSINESS_REJECTS:
            return Decision(OVER_BLOCKED, layer,
                            "a legitimate request was refused at %s; negative "
                            "results from this run may be unreliable until this "
                            "is explained" % layer)
        if layer == "business_reject":
            return Decision(OVER_BLOCKED, layer,
                            "a legitimate request was refused at the business "
                            "layer (%s)" % (attribution.remark or "no remark"))
        return Decision(UNCLEAR, layer, "outcome %r does not map to a verdict"
                        % layer)

    raise ValueError("unknown expectation %r (expected reject/accept/observe)"
                     % expectation)
