"""Re-validation and closure corpora.

EXTRACTED CAPABILITY (CAP-027, CAP-028).

Retesting a previously reported finding is a different job from finding it.
Three disciplines from the source are preserved because each exists to stop a
specific way a retest goes wrong:

1. **Verdicts come only from observed responses.** The client's own remediation
   status column is never consulted by the tooling. A retest that reads the
   status it is supposed to verify is not a retest.

2. **Baseline calibration is mandatory.** Every retest run starts with
   well-formed requests that must succeed. If a baseline fails, the negative
   results are not evidence of remediation -- they are evidence the harness,
   the credentials or the target state is wrong. The run is then INCONCLUSIVE,
   not "all controls present". This distinction is enforced in code below,
   because it is the single easiest way to produce a confidently wrong retest.

3. **Closure completes the matrix.** When a remediation item says "apply this
   consistently across all endpoints", testing the subset originally affected
   infers the rest. The gap is computed and the missing cells generated.
"""
import json

from .. import payload as PL
from ..case import Case
from ..payload import PayloadTemplate

BASELINE_PREFIX = "BASE"


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


def baseline_cases(profile, endpoints=None):
    """Oracle calibration: well-formed requests that a healthy target accepts.

    Declared ``expectation="accept"``, so a refusal surfaces as OVER-BLOCKED
    and ``assess_baseline`` below will mark the whole run inconclusive.
    """
    out = []
    for ep in (endpoints or profile.endpoint_ids):
        _, body = _wellformed(profile, ep)
        out.append(Case("%s-%s" % (BASELINE_PREFIX, ep), ep, "accept",
                        "Baseline: well-formed request to %r with fresh "
                        "identifiers (oracle calibration)" % ep,
                        family="BASELINE", phase="P0",
                        body=json.dumps(body), payload_class="benign",
                        severity_if_accepted="Informational",
                        state_mutating=True,
                        notes="if this does not succeed, negative results in "
                              "this run are not evidence of remediation"))
    return out


def assess_baseline(records):
    """Decide whether a run's baselines justify trusting its other results.

    *records* are result dicts carrying ``case_id`` and ``verdict``.
    Returns (trustworthy, summary).
    """
    from ...oracle import verdict as V
    baselines = [r for r in records
                 if str(r.get("case_id", "")).startswith(BASELINE_PREFIX + "-")]
    if not baselines:
        return False, ("no baseline cases were executed; without oracle "
                       "calibration the run cannot distinguish a working "
                       "control from a broken harness")
    failed = [r for r in baselines
              if r.get("verdict") != V.CONTROL_PRESENT]
    if failed:
        return False, ("%d of %d baseline case(s) did not succeed (%s); "
                       "negative results in this run are INCONCLUSIVE, not "
                       "evidence of remediation"
                       % (len(failed), len(baselines),
                          ", ".join(str(r.get("case_id")) for r in failed)))
    return True, "%d/%d baseline cases succeeded; oracle calibrated" \
        % (len(baselines), len(baselines))


class RetestItem(object):
    """One previously reported finding to be re-validated.

    ``remediation_items`` are typed, because the distinction decides what a
    retest can honestly claim:

      observable            -- externally testable; a verdict is possible
      not_externally_testable -- documentation or internal process; no verdict
      risk_accepted         -- the client has declined to remediate

    The source's reports drew this distinction in prose. Typing it means a
    report cannot quietly present an untestable item as verified.
    """

    KINDS = ("observable", "not_externally_testable", "risk_accepted")

    def __init__(self, finding_id, title, severity="Medium",
                 remediation_items=None, affected_endpoints=None, notes=""):
        self.finding_id = finding_id
        self.title = title
        self.severity = severity
        self.remediation_items = list(remediation_items or [])
        self.affected_endpoints = list(affected_endpoints or [])
        self.notes = notes
        for item in self.remediation_items:
            kind = item.get("kind")
            if kind not in self.KINDS:
                raise ValueError(
                    "finding %s: remediation item kind %r must be one of %s"
                    % (finding_id, kind, self.KINDS))

    def observable_items(self):
        return [i for i in self.remediation_items
                if i["kind"] == "observable"]

    def untestable_items(self):
        return [i for i in self.remediation_items
                if i["kind"] != "observable"]


def retest_cases(profile, item, probes):
    """Build cases for one retest item.

    *probes* is a list of dicts:
        {"id", "endpoint", "expectation", "description",
         "mutate": [(path, value), ...] | None,
         "raw": str | None, "method", "content_type",
         "header_overrides", "identity", "payload_class",
         "shallow_reject_required"}

    Keeping probes declarative means an engagement describes what to send
    without writing a generator.
    """
    out = []
    for probe in probes:
        ep = probe.get("endpoint") or (item.affected_endpoints[0]
                                       if item.affected_endpoints
                                       else profile.endpoint_ids[0])
        raw = probe.get("raw")
        if raw is None:
            _, body = _wellformed(profile, ep)
            for path, value in (probe.get("mutate") or []):
                body = PL.set_(body, path, value)
            body_text = json.dumps(body)
        else:
            body_text = raw
        out.append(Case(
            probe["id"], ep, probe.get("expectation", "reject"),
            probe["description"],
            family="RETEST", phase="RETEST", finding_id=item.finding_id,
            body=body_text, method=probe.get("method", "POST"),
            content_type=probe.get("content_type", "application/json"),
            header_overrides=probe.get("header_overrides") or {},
            identity=probe.get("identity"),
            payload_class=probe.get("payload_class", "benign"),
            severity_if_accepted=probe.get("severity", item.severity),
            state_mutating=probe.get("state_mutating", True),
            shallow_reject_required=probe.get("shallow_reject_required", False),
            spec_reference=probe.get("spec_reference", ""),
            notes=probe.get("notes", "")))
    return out


def closure_cases(profile, corpus, finding_id, endpoints=None,
                  probe_builder=None):
    """Complete a finding's coverage matrix across every endpoint.

    EXTRACTED CAPABILITY (CAP-028), mechanised. Reports which endpoints the
    finding was actually exercised against, and generates the missing cells.
    Returns (cases, gaps_filled).
    """
    endpoints = endpoints or profile.endpoint_ids
    covered = {c.endpoint for c in corpus if c.finding_id == finding_id}
    gaps = [e for e in endpoints if e not in covered]
    if not gaps or probe_builder is None:
        return [], gaps
    out = []
    for i, ep in enumerate(gaps, 1):
        for probe in probe_builder(ep):
            probe = dict(probe)
            probe["endpoint"] = ep
            probe["id"] = "CLOSE-%s-%s-%02d" % (finding_id, ep, i)
            probe.setdefault("description",
                             "Closure: %s exercised on %r to evidence "
                             "consistent application" % (finding_id, ep))
            out.extend(retest_cases(
                profile,
                RetestItem(finding_id, "closure", affected_endpoints=[ep]),
                [probe]))
    return out, gaps
