"""Proxy fidelity verification.

EXTRACTED CAPABILITY (CAP-022). The most original idea in the source toolkit,
and the one most worth generalising.

The problem: when traffic is routed through an intercepting proxy, the proxy
becomes part of the system under test. If it buffers a large body, normalises a
malformed one, or repairs a control character, then a negative result is the
*proxy's* behaviour rather than the target's -- and the assessment has quietly
measured the wrong thing. A clean-looking "the service rejected this" may mean
"the proxy never sent it".

So before trusting the edge cases a corpus depends on, prove the proxy
transmits them faithfully. Each probe is sent twice -- once direct, once
through the proxy -- and the two outcomes are compared. The profile declares
the expected outcome; disagreement between the two paths is the failure signal,
and that comparison is what makes the check target-independent.

A fidelity failure does not stop a run. It marks the affected payload classes
UNRELIABLE so the report can say which results cannot be trusted, which is more
useful than refusing to proceed.
"""
import json

PROBE_LARGE_BODY = "large_body"
PROBE_NUL_BYTE = "nul_byte"
PROBE_DUPLICATE_HEADER = "duplicate_header"
PROBE_MALFORMED_JSON = "malformed_json"

#: Which payload classes each probe's integrity underwrites. If a probe fails,
#: results for these classes are not dependable.
UNDERWRITES = {
    PROBE_LARGE_BODY: ["oversize"],
    PROBE_NUL_BYTE: ["malformed", "injection"],
    PROBE_DUPLICATE_HEADER: ["auth"],
    PROBE_MALFORMED_JSON: ["malformed", "structure"],
}


class ProbeResult(object):
    def __init__(self, name, direct_status, proxied_status, expected,
                 agree, verdict, detail, underwrites):
        self.name = name
        self.direct_status = direct_status
        self.proxied_status = proxied_status
        self.expected = expected
        self.agree = agree
        self.verdict = verdict          # PASS / FAIL / NOT VERIFIED
        self.detail = detail
        self.underwrites = list(underwrites)

    def as_dict(self):
        return {
            "probe": self.name, "direct_status": self.direct_status,
            "proxied_status": self.proxied_status, "expected": self.expected,
            "paths_agree": self.agree, "verdict": self.verdict,
            "detail": self.detail, "underwrites_payload_classes": self.underwrites,
        }

    def __repr__(self):
        return "<ProbeResult %s %s direct=%s proxied=%s>" % (
            self.name, self.verdict, self.direct_status, self.proxied_status)


def _send_both(transport, url, case_id, body, content_type="application/json",
               header_overrides=None):
    direct = transport.send(case_id + "-direct", url, body=body,
                            content_type=content_type,
                            header_overrides=header_overrides, use_proxy=False)
    proxied = transport.send(case_id + "-proxied", url, body=body,
                             content_type=content_type,
                             header_overrides=header_overrides, use_proxy=True)
    return direct, proxied


def _build_body(profile, endpoint_id, pad_field=None, pad_size=0,
                inject_nul=False, malformed=False):
    from framework.corpus.payload import PayloadTemplate, get as pget, set_ as pset
    tpl = PayloadTemplate(profile.template_for(endpoint_id), endpoint_id)
    ep = profile.endpoint(endpoint_id)
    spaces = profile.data.get("identifier_spaces") or {}
    ident = profile.identifier_for(endpoint_id) if ep.get("identifier_space") else None
    corr = (profile.generate_identifier("correlation")
            if (tpl.correlation_path and "correlation" in spaces)
            else (pget(tpl.body, tpl.correlation_path)
                  if tpl.correlation_path else None))
    body = tpl.instantiate(identifier=ident, correlation=corr)
    if pad_size:
        target = pad_field or tpl.note_path or tpl.identifier_path
        body = pset(body, target, "P" * pad_size)
    if inject_nul:
        body = pset(body, tpl.identifier_path, "SYNTH" + chr(0) + "0001")
    text = json.dumps(body)
    if malformed:
        text = text[:max(1, len(text) // 2)]
    return text


def probe_large_body(profile, transport, endpoint_id, expected_status=None,
                     size=200000):
    """Does an oversized body still reach the server's size limit?

    A proxy that buffers or truncates the body would make the target look as
    though it enforces no limit -- or as though it enforces one it does not.
    """
    url = profile.url_for(endpoint_id)
    body = _build_body(profile, endpoint_id, pad_size=size)
    direct, proxied = _send_both(transport, url, "fid-large", body)
    agree = direct.status == proxied.status
    if not direct.ok_transport and not proxied.ok_transport:
        return ProbeResult(PROBE_LARGE_BODY, direct.status, proxied.status,
                           expected_status, None, "NOT VERIFIED",
                           "neither path returned a response",
                           UNDERWRITES[PROBE_LARGE_BODY])
    if not agree:
        return ProbeResult(
            PROBE_LARGE_BODY, direct.status, proxied.status, expected_status,
            False, "FAIL",
            "the proxy altered the outcome for a %d-byte body (direct %s, "
            "proxied %s); oversize results obtained through the proxy are not "
            "dependable" % (size, direct.status, proxied.status),
            UNDERWRITES[PROBE_LARGE_BODY])
    if expected_status and str(expected_status) != str(proxied.status):
        return ProbeResult(
            PROBE_LARGE_BODY, direct.status, proxied.status, expected_status,
            True, "NOT VERIFIED",
            "both paths agree on HTTP %s but the profile expects %s; the "
            "expectation may be stale rather than the proxy at fault"
            % (proxied.status, expected_status),
            UNDERWRITES[PROBE_LARGE_BODY])
    return ProbeResult(PROBE_LARGE_BODY, direct.status, proxied.status,
                       expected_status, True, "PASS",
                       "both paths returned HTTP %s; the body traverses the "
                       "proxy intact" % proxied.status,
                       UNDERWRITES[PROBE_LARGE_BODY])


def probe_nul_byte(profile, transport, endpoint_id, expected_status=None):
    """Does an escaped NUL reach the application unaltered?"""
    url = profile.url_for(endpoint_id)
    body = _build_body(profile, endpoint_id, inject_nul=True)
    direct, proxied = _send_both(transport, url, "fid-nul", body)
    agree = direct.status == proxied.status
    verdict = "PASS" if agree else "FAIL"
    detail = ("both paths returned HTTP %s; control characters survive the "
              "proxy" % proxied.status) if agree else \
        ("the proxy changed the outcome for an escaped NUL (direct %s, "
         "proxied %s); malformed-input and injection results obtained through "
         "the proxy are not dependable" % (direct.status, proxied.status))
    if not direct.ok_transport and not proxied.ok_transport:
        verdict, detail = "NOT VERIFIED", "neither path returned a response"
    return ProbeResult(PROBE_NUL_BYTE, direct.status, proxied.status,
                       expected_status, agree, verdict, detail,
                       UNDERWRITES[PROBE_NUL_BYTE])


def probe_duplicate_header(profile, transport, endpoint_id):
    """Are duplicate headers forwarded as sent, in order?

    A proxy that collapses duplicates makes duplicate-credential precedence
    untestable -- and that is a High-severity case class.
    """
    url = profile.url_for(endpoint_id)
    body = _build_body(profile, endpoint_id)
    overrides = {"X-APIScan-Fidelity": ["first", "second"]}
    direct, proxied = _send_both(transport, url, "fid-dup", body,
                                 header_overrides=overrides)
    agree = direct.status == proxied.status
    return ProbeResult(
        PROBE_DUPLICATE_HEADER, direct.status, proxied.status, None, agree,
        "PASS" if agree else "FAIL",
        ("both paths returned HTTP %s; duplicate headers are not collapsed in "
         "a way that changes the outcome" % proxied.status) if agree else
        ("the proxy changed the outcome when duplicate headers were sent "
         "(direct %s, proxied %s); duplicate-credential precedence cannot be "
         "tested reliably through this proxy"
         % (direct.status, proxied.status)),
        UNDERWRITES[PROBE_DUPLICATE_HEADER])


def probe_malformed_json(profile, transport, endpoint_id):
    """Is a truncated body forwarded without repair?"""
    url = profile.url_for(endpoint_id)
    body = _build_body(profile, endpoint_id, malformed=True)
    direct, proxied = _send_both(transport, url, "fid-malformed", body)
    agree = direct.status == proxied.status
    return ProbeResult(
        PROBE_MALFORMED_JSON, direct.status, proxied.status, None, agree,
        "PASS" if agree else "FAIL",
        ("both paths returned HTTP %s; malformed bodies traverse the proxy "
         "unrepaired" % proxied.status) if agree else
        ("the proxy changed the outcome for a truncated body (direct %s, "
         "proxied %s); malformed-input results are not dependable"
         % (direct.status, proxied.status)),
        UNDERWRITES[PROBE_MALFORMED_JSON])


ALL_PROBES = {
    PROBE_LARGE_BODY: probe_large_body,
    PROBE_NUL_BYTE: probe_nul_byte,
    PROBE_DUPLICATE_HEADER: probe_duplicate_header,
    PROBE_MALFORMED_JSON: probe_malformed_json,
}


def verify(profile, transport, endpoint_id=None, probes=None):
    """Run the fidelity suite. Returns (results, unreliable_payload_classes)."""
    endpoint_id = endpoint_id or profile.endpoint_ids[0]
    expectations = profile.data.get("fidelity_expectations") or {}
    wanted = probes or list(ALL_PROBES)
    results = []
    for name in wanted:
        fn = ALL_PROBES[name]
        if name == PROBE_LARGE_BODY:
            results.append(fn(profile, transport, endpoint_id,
                              expected_status=expectations.get(
                                  "large_body_status"),
                              size=expectations.get("large_body_bytes",
                                                    200000)))
        elif name == PROBE_NUL_BYTE:
            results.append(fn(profile, transport, endpoint_id,
                              expected_status=expectations.get(
                                  "nul_byte_status")))
        else:
            results.append(fn(profile, transport, endpoint_id))

    unreliable = set()
    for r in results:
        if r.verdict == "FAIL":
            unreliable.update(r.underwrites)
    return results, sorted(unreliable)


def summarise(results, unreliable):
    passed = sum(1 for r in results if r.verdict == "PASS")
    failed = sum(1 for r in results if r.verdict == "FAIL")
    unknown = sum(1 for r in results if r.verdict == "NOT VERIFIED")
    lines = ["proxy fidelity: %d pass, %d fail, %d not verified"
             % (passed, failed, unknown)]
    for r in results:
        lines.append("  %-18s %-13s %s" % (r.name, r.verdict, r.detail))
    if unreliable:
        lines.append("")
        lines.append("RESULTS FOR THESE PAYLOAD CLASSES ARE NOT DEPENDABLE "
                     "THROUGH THIS PROXY: %s" % ", ".join(unreliable))
        lines.append("Re-measure them on the direct path, or state the "
                     "limitation in the report.")
    return "\n".join(lines)
