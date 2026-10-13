"""Case execution.

Ties the pieces together in the order that matters:

    scope gate -> transport -> evidence capture -> layer attribution ->
    verdict -> detectors -> record

The scope gate comes first and is not optional. A case the engagement has not
authorised is never sent, and the skip is recorded so coverage accounting can
distinguish "not executed" from "executed and passed" -- a distinction the
report depends on.

Detectors run on every response regardless of verdict, because a disclosure in
the body of an otherwise correctly rejected request is still a finding.
"""
import json
import time

from .core.errors import FrameworkError
from .core.transport import Transport
from .evidence.provenance import CaptureMethod
from .governance.limits import Budget, RunLimits
from .governance.scope import ScopePolicy
from .oracle import detectors as DT
from .oracle import layers as L
from .oracle import verdict as V

SKIPPED = "SKIPPED"
#: A case that was in scope but never sent because the run hit a ceiling or a
#: stop condition. Distinct from SKIPPED so coverage accounting can say "the
#: run stopped early" rather than "the engagement excluded this".
NOT_REACHED = "NOT-REACHED"


class Result(object):
    """One executed (or skipped) case, flattened for reporting."""

    def __init__(self, **kw):
        self.data = kw

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)

    def as_dict(self):
        return dict(self.data)


class Runner(object):
    def __init__(self, profile, auth_provider, evidence_store,
                 scope_policy=None, via_proxy=True, verdict_policy=None,
                 detector_rules=None, delay_s=None, capture_method=None,
                 limits=None, mode=None):
        self.profile = profile
        self.auth = auth_provider
        self.store = evidence_store
        self.scope = scope_policy or ScopePolicy.default()
        self.via_proxy = via_proxy
        self.verdict_policy = (
            verdict_policy
            or (profile.response_model.get("verdict_policy") or "layered"))
        self.rules = detector_rules if detector_rules is not None \
            else DT.load_rules()
        self.mode = mode
        #: The scope policy narrowed by the engagement mode. Both have to
        #: permit a request, and this is the object that decides.
        if mode is not None:
            self.scope = self.scope.with_mode(mode)
        self.limits = limits or (mode.limits if mode is not None
                                 else RunLimits())
        self.budget = Budget(self.limits)
        self.delay_s = max(
            (profile.transport.get("delay_s", 0.25)
             if delay_s is None else delay_s),
            self.limits.min_delay_s)
        self.capture_method = capture_method or (
            CaptureMethod.PROXY if via_proxy else CaptureMethod.DIRECT)
        self.transport = Transport(profile, auth_provider,
                                   body_dir=evidence_store.run_dir,
                                   scope_policy=self.scope,
                                   via_proxy=via_proxy,
                                   limits=self.limits, budget=self.budget)

    # -- single case -----------------------------------------------------
    def run_case(self, case, today=None):
        # via_proxy matters to the gate: a policy may require every request to
        # traverse the proxy, and the runner is the only place that knows which
        # transport this case will actually use.
        permitted, reason = self.scope.evaluate(case, today,
                                                via_proxy=self.via_proxy)
        if not permitted:
            return self.store.record(self._skip_record(case, reason))

        may_continue, stop_reason = self.budget.check()
        if not may_continue:
            return self.store.record(
                self._skip_record(case, stop_reason, verdict=NOT_REACHED))

        url = self.profile.url_for(case.endpoint)
        trace = self.store.trace_path(case.id)
        # The case IS the probe: the transport re-evaluates it at the point
        # the socket is opened, so a caller that bypassed this runner cannot
        # bypass the gate.
        try:
            response = self.transport.send(
                case.id, url, method=case.method,
                identity=case.identity or self.auth.default_identity,
                header_overrides=case.header_overrides,
                content_type=case.content_type, body=case.body,
                trace_file=trace, probe=case, today=today,
                use_proxy=(case.use_proxy if case.use_proxy is not None
                           else self.via_proxy))
        except FrameworkError as exc:
            # The gate and the budget are evaluated twice: once here, for the
            # record, and again inside the transport at the moment the socket
            # would open. They should always agree. If they ever do not, the
            # safe outcome is that this case is refused and recorded -- not
            # that an exception unwinds the loop and discards the evidence
            # already captured for every case before it.
            return self.store.record(self._skip_record(
                case, "refused at the transport: %s" % exc,
                verdict=V.ERROR))
        self.store.write_response(case.id, response)

        attribution = L.attribute(response, self.profile.response_model)
        decision = V.decide(case.expectation, attribution,
                            policy=self.verdict_policy,
                            shallow_reject_required=case.shallow_reject_required)

        hits = DT.scan_disclosure(response.body or "", self.rules)
        reflection = DT.scan_reflection(
            case.submitted_identifier, response.body or "",
            payload_class=case.payload_class)
        if reflection:
            hits.append(reflection)
        markers = [m for m in case.markers
                   if m and m.lower() in (response.body or "").lower()]

        used_proxy = (case.use_proxy if case.use_proxy is not None
                      else self.via_proxy)
        method = (self.capture_method if used_proxy else CaptureMethod.DIRECT)

        return self.store.record(Result(
            case_id=case.id, family=case.family, phase=case.phase,
            endpoint=case.endpoint, method_http=case.method,
            content_type=case.content_type,
            # The identity ACTUALLY used, not the one the case left unset. A
            # finding cites its baseline by identity, and "default" is not a
            # name anyone can check against the engagement's credentials.
            identity=(case.identity or self.auth.default_identity),
            description=case.description, expectation=case.expectation,
            finding_id=case.finding_id, owasp=case.owasp,
            spec_reference=case.spec_reference,
            payload_class=case.payload_class,
            state_mutating=case.state_mutating,
            severity_if_accepted=case.severity_if_accepted,
            executed=True, scope_reason=reason,
            http_status=response.status,
            layer=attribution.layer, layer_basis=attribution.basis,
            remark=attribution.remark,
            envelope_code=(attribution.envelope.code
                           if attribution.envelope
                           and attribution.envelope.present else None),
            verdict=decision.verdict, verdict_reason=decision.reason,
            control_depth=decision.control_depth,
            detector_hits=[h.as_dict() for h in hits],
            markers_matched=markers,
            capture_method=method,
            request_file=self.store.relative(self.store.request_path(case.id))
            if case.body is not None else "",
            response_file=self.store.relative(
                self.store.response_path(case.id)),
            trace_file=self.store.relative(trace),
            time_total=response.meta.get("time_total"),
            via=response.meta.get("via"),
            curl_rc=response.meta.get("curl_rc"),
            tls_verification=response.meta.get("tls_verification"),
            body_truncated=bool(response.meta.get("body_truncated")),
            header_stream=response.meta.get("header_stream"),
            notes=case.notes,
        ).as_dict())

    def _skip_record(self, case, reason, verdict=SKIPPED):
        return Result(
            case_id=case.id, family=case.family, phase=case.phase,
            endpoint=case.endpoint, method_http=case.method,
            description=case.description, expectation=case.expectation,
            finding_id=case.finding_id, owasp=case.owasp,
            payload_class=case.payload_class,
            state_mutating=case.state_mutating,
            severity_if_accepted=case.severity_if_accepted,
            executed=False, verdict=verdict, scope_reason=reason,
            verdict_reason="not executed: %s" % reason,
            http_status=None, layer=None, detector_hits=[],
            markers_matched=[], capture_method=None,
            notes=case.notes).as_dict()

    # -- whole corpus ----------------------------------------------------
    def run(self, cases, progress=None, today=None):
        out = []
        total = len(cases)
        self.budget.start()
        for i, case in enumerate(cases, 1):
            rec = self.run_case(case, today=today)
            out.append(rec)
            if progress:
                progress(i, total, rec)
            if rec.get("executed") and self.delay_s:
                time.sleep(self.delay_s)
        return out

    def stop_report(self):
        """What stopped the run, if anything did. Goes into run metadata."""
        return self.budget.as_dict()


def default_progress(i, total, rec):
    flag = {
        V.CONTROL_PRESENT: "[ ok ]", V.CONTROL_ABSENT: "[FIND]",
        V.OVER_BLOCKED: "[OVER]", V.BLOCKED: "[blkd]",
        V.ERROR: "[ err]", V.OBSERVED: "[obsv]", V.UNCLEAR: "[  ? ]",
        SKIPPED: "[skip]", NOT_REACHED: "[stop]",
    }.get(rec.get("verdict"), "[    ]")
    extra = ""
    if rec.get("detector_hits"):
        extra = "  LEAK:" + ",".join(h["rule_id"] for h in rec["detector_hits"])
    print("[%3d/%3d] %s %-12s %-16s %-5s %-18s %s%s"
          % (i, total, flag, str(rec.get("case_id"))[:12],
             str(rec.get("endpoint"))[:16], str(rec.get("http_status") or "-"),
             str(rec.get("layer") or "-")[:18],
             str(rec.get("verdict"))[:16], extra))


def summarise(records):
    """Counts by verdict, plus the things a summary must not hide."""
    from collections import Counter
    verdicts = Counter(r.get("verdict") for r in records)
    executed = sum(1 for r in records if r.get("executed"))
    leaks = sum(1 for r in records if r.get("detector_hits"))
    return {
        "total": len(records),
        "executed": executed,
        "skipped": verdicts.get(SKIPPED, 0),
        "not_reached": verdicts.get(NOT_REACHED, 0),
        "blocked": verdicts.get(V.BLOCKED, 0),
        "errors": verdicts.get(V.ERROR, 0),
        "control_present": verdicts.get(V.CONTROL_PRESENT, 0),
        "control_absent": verdicts.get(V.CONTROL_ABSENT, 0),
        "over_blocked": verdicts.get(V.OVER_BLOCKED, 0),
        "observed": verdicts.get(V.OBSERVED, 0),
        "unclear": verdicts.get(V.UNCLEAR, 0),
        "with_detector_hits": leaks,
        "by_verdict": dict(verdicts),
    }


def reclassify(run_dir, cases, profile, verdict_policy=None,
               detector_rules=None):
    """Re-judge a completed run from stored responses, sending nothing.

    EXTRACTED CAPABILITY (CAP-014). A classifier change costs no extra traffic
    and no repeated state mutation, which matters when cases are mutating and
    the target is a live system. It is also how the framework's own regression
    tests pin oracle behaviour against recorded fixtures.
    """
    import os

    from .evidence.store import parse_response_file

    rules = detector_rules if detector_rules is not None else DT.load_rules()
    policy = verdict_policy or (profile.response_model.get("verdict_policy")
                                or "layered")
    by_id = {c.id: c for c in cases}
    out = []

    class _Stored(object):
        def __init__(self, status, headers, body):
            self.status = status
            self.headers = headers
            self.body = body
            self.meta = {"via": "stored", "curl_rc": 0}

        @property
        def ok_transport(self):
            return self.status not in ("000", "", None)

        @property
        def status_int(self):
            try:
                return int(self.status)
            except (TypeError, ValueError):
                return 0

        def header(self, name):
            want = name.lower()
            for line in (self.headers or "").splitlines():
                if ":" in line and \
                        line.split(":", 1)[0].strip().lower() == want:
                    return line.split(":", 1)[1].strip()
            return None

    for case_id, case in sorted(by_id.items()):
        from .core.pathguard import safe_join
        path = safe_join(run_dir, "%s.resp.txt" % case_id,
                         what="stored response")
        if not os.path.exists(path):
            continue
        # Parsed by declared section length, so a target-controlled body
        # cannot relocate the header boundary and change its own verdict.
        stored = parse_response_file(path)
        status, headers, body = (stored["status"], stored["headers"],
                                 stored["body"])
        resp = _Stored(status, headers, body)
        attribution = L.attribute(resp, profile.response_model)
        decision = V.decide(case.expectation, attribution, policy=policy,
                            shallow_reject_required=case.shallow_reject_required)
        hits = DT.scan_disclosure(body, rules)
        reflection = DT.scan_reflection(case.submitted_identifier, body,
                                        payload_class=case.payload_class)
        if reflection:
            hits.append(reflection)
        out.append({
            "case_id": case_id, "endpoint": case.endpoint,
            "expectation": case.expectation, "http_status": status,
            "layer": attribution.layer, "verdict": decision.verdict,
            "verdict_reason": decision.reason,
            "control_depth": decision.control_depth,
            "detector_hits": [h.as_dict() for h in hits],
            "executed": True, "reclassified": True,
            "finding_id": case.finding_id, "phase": case.phase,
            "family": case.family,
            "severity_if_accepted": case.severity_if_accepted,
            "evidence_format": ("legacy-heuristic" if stored["legacy_format"]
                                else "length-declared"),
            "body_truncated": stored["truncated"],
        })
    return out
