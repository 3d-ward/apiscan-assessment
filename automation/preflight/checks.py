"""Preflight readiness gate.

EXTRACTED CAPABILITY (CAP-021), restructured as a registry.

The source's preflight script was a linear sequence ordered so that the first
failure was the thing to fix, with a concrete remedy attached to every failure.
Both properties are preserved -- they are what make a preflight useful rather
than merely noisy -- but the checks are now pluggable units with declared
ordering, severity and applicability, so an engagement can add a check without
editing the engine, and a check that does not apply is skipped rather than
reported as a confusing pass.

Severity semantics:
  FAIL  a blocker. The run must not proceed.
  WARN  the run can proceed but something will be degraded; say what.
  PASS  verified.
  SKIP  not applicable to this profile.

ENGINEERING IMPROVEMENT: machine-readable output (``--json``) so a preflight
can gate a pipeline, and a ``NOT VERIFIED`` outcome distinct from a pass for
checks whose dependencies are absent.
"""
import json
import os
import shutil
import socket
import subprocess
import time
from urllib.parse import urlparse

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"
SKIP = "SKIP"
NOT_VERIFIED = "NOT VERIFIED"

BLOCKING = (FAIL,)


class CheckResult(object):
    def __init__(self, check_id, name, status, detail, remedy=""):
        self.check_id = check_id
        self.name = name
        self.status = status
        self.detail = detail
        self.remedy = remedy

    def as_dict(self):
        return {"id": self.check_id, "name": self.name, "status": self.status,
                "detail": self.detail, "remedy": self.remedy}

    def __repr__(self):
        return "<CheckResult %s %s>" % (self.check_id, self.status)


class Check(object):
    def __init__(self, check_id, name, order, fn, applies=None):
        self.check_id = check_id
        self.name = name
        self.order = order
        self.fn = fn
        self.applies = applies or (lambda ctx: True)

    def run(self, ctx):
        if not self.applies(ctx):
            return CheckResult(self.check_id, self.name, SKIP,
                               "not applicable to this profile")
        try:
            return self.fn(ctx, self)
        except Exception as exc:                        # noqa: BLE001
            return CheckResult(self.check_id, self.name, FAIL,
                               "check raised %s: %s"
                               % (type(exc).__name__, str(exc)[:200]),
                               "this is a defect in the check itself")


REGISTRY = []


def register(check_id, name, order, applies=None):
    def decorator(fn):
        REGISTRY.append(Check(check_id, name, order, fn, applies))
        return fn
    return decorator


def _sh(cmd, timeout=25, stdin_data=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, errors="replace",
                              input=stdin_data)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except OSError as exc:
        return 127, "", str(exc)


def _uses_proxy(ctx):
    return bool(ctx.get("profile") and ctx["profile"].proxy)


# -- 1. toolchain --------------------------------------------------------
@register("tool.curl", "curl available", 10)
def _curl(ctx, chk):
    path = shutil.which("curl")
    if not path:
        return CheckResult(chk.check_id, chk.name, FAIL, "curl not found",
                           "curl is the transport; install it before running")
    rc, out, _ = _sh(["curl", "--version"])
    return CheckResult(chk.check_id, chk.name, PASS,
                       out.splitlines()[0][:90] if out else path)


@register("tool.openssl", "openssl available", 11)
def _openssl(ctx, chk):
    path = shutil.which("openssl")
    if not path:
        return CheckResult(chk.check_id, chk.name, WARN, "openssl not found",
                           "TLS posture checks and CA fingerprinting will be "
                           "unavailable; HTTP assessment is unaffected")
    rc, out, err = _sh(["openssl", "version"])
    return CheckResult(chk.check_id, chk.name, PASS,
                       (out or err).strip()[:90])


# -- 2. profile ----------------------------------------------------------
@register("profile.loaded", "target profile loads and validates", 20)
def _profile(ctx, chk):
    profile = ctx.get("profile")
    if profile is None:
        return CheckResult(chk.check_id, chk.name, FAIL, "no profile supplied",
                           "pass --profile <path>")
    return CheckResult(
        chk.check_id, chk.name, PASS,
        "%s: %d endpoint(s), %d identit(ies), %d secret ref(s) resolved"
        % (profile.name, len(profile.endpoint_ids), len(profile.identities),
           len(profile.resolved_env)))


@register("profile.placeholders", "target profile is filled in, not the scaffold", 22)
def _placeholders(ctx, chk):
    """Refuse to proceed while the profile still describes the example.

    ``init-engagement`` copies a synthetic profile that is schema-valid and
    fully runnable. Nothing else notices if it is never edited, so a scan can
    complete successfully against the RFC 2606 reserved host -- real traffic
    to an uninvolved party, and a report whose every number is about nothing.
    This fires before any request is sent.
    """
    profile = ctx["profile"]
    found = []
    base = (profile.transport.get("base_url") or "")
    for reserved in ("example.com", "example.net", "example.org"):
        if reserved in base:
            found.append("transport.base_url still points at the reserved "
                         "host %s" % reserved)
            break
    identity = profile.data.get("identity", {})
    for field in ("name", "description", "engagement_ref"):
        value = str(identity.get(field) or "")
        if "REPLACE" in value.upper():
            found.append("identity.%s is still the placeholder text" % field)
    if str(identity.get("engagement_ref") or "") in ("EXAMPLE-0000",):
        found.append("identity.engagement_ref is still the example value")
    if not found:
        return CheckResult(chk.check_id, chk.name, PASS,
                           "no scaffold placeholders remain")
    return CheckResult(
        chk.check_id, chk.name, FAIL, "; ".join(found),
        "edit profile.json and replace the synthetic values with the real "
        "target: base URL, identity name/description/engagement_ref, "
        "endpoints and identifier formats. The scaffold is a template, not a "
        "target.")


@register("profile.secrets", "credentials resolved from the environment", 21)
def _secrets(ctx, chk):
    profile = ctx.get("profile")
    if profile is None:
        return CheckResult(chk.check_id, chk.name, SKIP, "no profile")
    if not profile.resolved_env:
        return CheckResult(
            chk.check_id, chk.name, WARN,
            "no ${ENV:...} references were resolved",
            "if this target needs credentials, they are not being supplied; "
            "an entire run can otherwise produce authentication findings that "
            "are artifacts of the harness")
    return CheckResult(chk.check_id, chk.name, PASS,
                       "resolved: %s" % ", ".join(profile.resolved_env))


# -- 3. proxy ------------------------------------------------------------
@register("proxy.listener", "proxy listener accepting connections", 30,
          applies=_uses_proxy)
def _listener(ctx, chk):
    parsed = urlparse(ctx["profile"].proxy)
    host, port = parsed.hostname, parsed.port or 8080
    sock = socket.socket()
    sock.settimeout(3)
    try:
        ok = sock.connect_ex((host, port)) == 0
    finally:
        sock.close()
    if not ok:
        return CheckResult(
            chk.check_id, chk.name, FAIL,
            "nothing accepting connections on %s:%d" % (host, port),
            "start the proxy and bind its listener to %s:%d, or clear "
            "transport.proxy in the profile to run direct" % (host, port))
    return CheckResult(chk.check_id, chk.name, PASS,
                       "%s:%d accepting connections" % (host, port))


@register("proxy.forwarding", "proxy forwards rather than holds requests", 31,
          applies=_uses_proxy)
def _forwarding(ctx, chk):
    from tools.proxy import health
    probe = ctx.get("proxy_probe_url") or health.DEFAULT_PROBE_URL
    result = health.check(ctx["profile"].proxy, probe)
    if not result.healthy:
        return CheckResult(chk.check_id, chk.name, FAIL, result.detail,
                           result.remedy)
    return CheckResult(chk.check_id, chk.name, PASS, result.detail)


@register("proxy.ca", "proxy CA material consistent", 32, applies=_uses_proxy)
def _ca(ctx, chk):
    from tools.proxy import ca
    verify = (ctx["profile"].transport.get("tls_verify") or {})
    ca_path = verify.get("ca_path")
    if verify.get("mode") != "ca" or not ca_path:
        return CheckResult(
            chk.check_id, chk.name, WARN,
            "TLS verification is disabled for the proxied path",
            "acceptable while a proxy terminates TLS, but set tls_verify.mode "
            "to 'ca' with a fetched CA to verify the proxy strictly")
    if not os.path.exists(ca_path):
        return CheckResult(chk.check_id, chk.name, FAIL,
                           "CA file not found at %s" % ca_path,
                           "fetch it from the proxy control endpoint")
    matches, detail = ca.compare(ctx["profile"].proxy, ca_path,
                                 ctx.get("proxy_control_url")
                                 or ca.DEFAULT_CONTROL_URL)
    if matches is True:
        return CheckResult(chk.check_id, chk.name, PASS, detail)
    if matches is False:
        return CheckResult(chk.check_id, chk.name, WARN, detail,
                           "re-fetch the CA from the proxy")
    return CheckResult(chk.check_id, chk.name, NOT_VERIFIED, detail)


# -- 4. reachability -----------------------------------------------------
@register("target.reachable", "target answers on the configured path", 40)
def _reachable(ctx, chk):
    profile = ctx["profile"]
    if ctx.get("offline"):
        return CheckResult(chk.check_id, chk.name, SKIP,
                           "offline mode: no request was sent")
    transport = ctx.get("transport")
    if transport is None:
        return CheckResult(chk.check_id, chk.name, SKIP, "no transport built")
    endpoint = profile.endpoint_ids[0]
    resp = transport.send("preflight-reach", profile.url_for(endpoint),
                          method="POST", body="{}")
    if not resp.ok_transport:
        return CheckResult(
            chk.check_id, chk.name, FAIL,
            "no response from %s (%s)"
            % (profile.url_for(endpoint),
               resp.meta.get("stderr", "")[:120] or "transport error"),
            "check the base URL, DNS, network path and any client certificate "
            "requirement")
    markers = (profile.response_model.get("edge_block_markers") or [])
    for marker in markers:
        if marker and marker in (resp.body or ""):
            return CheckResult(
                chk.check_id, chk.name, FAIL,
                "an edge control refused the request: %r" % marker,
                "every case will be recorded BLOCKED and the application will "
                "not be tested. Supply the required client certificate (inside "
                "the proxy if one is in the path, since the proxy terminates "
                "TLS and performs the upstream handshake)")
    return CheckResult(chk.check_id, chk.name, PASS,
                       "HTTP %s from %s" % (resp.status,
                                            profile.url_for(endpoint)))


@register("target.oracle", "a well-formed request succeeds (oracle "
                           "calibration)", 41)
def _oracle(ctx, chk):
    if ctx.get("offline") or ctx.get("transport") is None:
        return CheckResult(chk.check_id, chk.name, SKIP,
                           "offline mode: no request was sent")
    from framework.corpus.generators.retest import baseline_cases
    from framework.oracle import layers as L
    from framework.oracle import verdict as V
    profile = ctx["profile"]
    transport = ctx["transport"]
    case = baseline_cases(profile, endpoints=[profile.endpoint_ids[0]])[0]
    resp = transport.send("preflight-oracle", profile.url_for(case.endpoint),
                          method=case.method, body=case.body,
                          content_type=case.content_type)
    attribution = L.attribute(resp, profile.response_model)
    decision = V.decide("accept", attribution)
    if decision.verdict == V.CONTROL_PRESENT:
        return CheckResult(chk.check_id, chk.name, PASS,
                           "HTTP %s -> %s; the oracle is calibrated"
                           % (resp.status, attribution.layer))
    return CheckResult(
        chk.check_id, chk.name, WARN,
        "a well-formed request did not succeed (HTTP %s -> %s, %s)"
        % (resp.status, attribution.layer, decision.verdict),
        "until this is explained, a negative result cannot be distinguished "
        "from a broken harness and the run should be treated as INCONCLUSIVE")


# -- 5. proxy fidelity ---------------------------------------------------
@register("proxy.fidelity", "proxy transmits edge cases faithfully", 50,
          applies=lambda ctx: (_uses_proxy(ctx) and not ctx.get("offline")
                               and ctx.get("transport") is not None
                               and (ctx["profile"].data.get(
                                   "fidelity_expectations") or {}
                               ).get("enabled", False)))
def _fidelity(ctx, chk):
    from tools.proxy import fidelity
    results, unreliable = fidelity.verify(ctx["profile"], ctx["transport"])
    ctx["fidelity_results"] = [r.as_dict() for r in results]
    ctx["unreliable_payload_classes"] = unreliable
    failed = [r for r in results if r.verdict == FAIL]
    if failed:
        return CheckResult(
            chk.check_id, chk.name, WARN,
            "%d fidelity probe(s) failed; results for payload class(es) %s are "
            "not dependable through this proxy"
            % (len(failed), ", ".join(unreliable)),
            "re-measure those classes on the direct path, or record the "
            "limitation in the report's coverage section")
    return CheckResult(chk.check_id, chk.name, PASS,
                       "%d probe(s) passed; the proxy does not alter the edge "
                       "cases the corpus depends on" % len(results))


# -- 6. evidence and output ---------------------------------------------
@register("evidence.writable", "evidence directory usable and outside the "
                               "framework", 60)
def _evidence(ctx, chk):
    from framework.core.errors import PathGuardError
    from framework.core.pathguard import ensure_engagement_dir
    root = ctx.get("evidence_root")
    if not root:
        return CheckResult(chk.check_id, chk.name, SKIP,
                           "no evidence root configured")
    try:
        resolved = ensure_engagement_dir(root)
    except PathGuardError as exc:
        return CheckResult(
            chk.check_id, chk.name, FAIL, str(exc),
            "point --evidence at a directory inside the engagement workspace, "
            "outside the framework tree")
    free_gb = shutil.disk_usage(resolved).free / 1e9
    if free_gb < 1:
        return CheckResult(chk.check_id, chk.name, WARN,
                           "%s writable but only %.1f GB free"
                           % (resolved, free_gb),
                           "free space before capturing evidence")
    return CheckResult(chk.check_id, chk.name, PASS,
                       "%s (%.1f GB free)" % (resolved, free_gb))


# -- 7. reporting and capture dependencies ------------------------------
@register("deps.reporting", "report renderers available", 70)
def _reporting(ctx, chk):
    from framework.reporting.renderers import xlsx
    if xlsx.available():
        note = "markdown, csv and xlsx available"
        if not xlsx.pillow_available():
            return CheckResult(
                chk.check_id, chk.name, WARN,
                note + "; Pillow is absent so PoC images cannot be embedded "
                       "in the workbook",
                "python3 -m pip install Pillow (the workbook will reference "
                "image paths instead)")
        return CheckResult(chk.check_id, chk.name, PASS,
                           note + "; image embedding available")
    return CheckResult(chk.check_id, chk.name, WARN,
                       "openpyxl absent: markdown and csv only",
                       "python3 -m pip install openpyxl for the workbook")


@register("deps.capture", "PoC capture available", 71)
def _capture(ctx, chk):
    from tools.capture import render, window
    browser = render.find_browser()
    win = window.availability()
    parts = []
    parts.append("render(html): available")
    parts.append("render(png): %s" % ("available" if browser else "NO BROWSER"))
    parts.append("window capture: %s"
                 % ("available" if win["usable"] else "unavailable"))
    if browser:
        return CheckResult(chk.check_id, chk.name, PASS, "; ".join(parts))
    return CheckResult(
        chk.check_id, chk.name, WARN, "; ".join(parts),
        "install Chrome/Chromium for PNG evidence, or use the HTML artifact "
        "path which needs no browser")


# -- runner --------------------------------------------------------------
def run(ctx, stop_on_fail=True, quiet=False):
    """Run every applicable check in order. Returns (results, blocked)."""
    results = []
    blocked = False
    for check in sorted(REGISTRY, key=lambda c: c.order):
        result = check.run(ctx)
        results.append(result)
        if not quiet:
            tag = {PASS: "  PASS", WARN: "  WARN", FAIL: "  FAIL",
                   SKIP: "  skip", NOT_VERIFIED: "  ----"}[result.status]
            print("%s  %-46s %s" % (tag, result.name, result.detail))
            if result.remedy and result.status in (FAIL, WARN):
                print("        -> %s" % result.remedy)
        if result.status in BLOCKING:
            blocked = True
            if stop_on_fail:
                if not quiet:
                    print("\nSTOP: the first blocker is the thing to fix. "
                          "Later checks were not run.")
                break
    return results, blocked


def summarise(results):
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def to_json(results, ctx=None):
    return json.dumps({
        "checks": [r.as_dict() for r in results],
        "summary": summarise(results),
        "ready": not any(r.status in BLOCKING for r in results),
        "unreliable_payload_classes": (ctx or {}).get(
            "unreliable_payload_classes", []),
    }, indent=2)


@register("deps.tls", "transport-posture tooling available", 72)
def _tls_tools(ctx, chk):
    """Report what THIS host can do, so a stale table in the docs never
    stands in for a fact about the machine the assessment runs on.

    Cipher enumeration is the only part that needs a third-party tool. When it
    is missing the module returns NOT VERIFIED with a remedy, so the run is
    still honest -- but the operator should learn that before the engagement,
    not from a gap in the report.
    """
    from framework.modules import tls_posture
    tools = tls_posture.tool_availability()
    have = sorted(k for k, v in tools.items() if v)
    missing = sorted(k for k, v in tools.items() if not v)
    detail = "available: %s" % (", ".join(have) or "none")
    if missing:
        detail += " | absent: %s" % ", ".join(missing)
    if not tools.get("openssl"):
        return CheckResult(
            chk.check_id, chk.name, FAIL, detail,
            "install openssl; without it no transport-layer evidence can be "
            "captured at all")
    if not (tools.get("nmap") or tools.get("testssl")):
        return CheckResult(
            chk.check_id, chk.name, WARN,
            detail + "; cipher enumeration will report NOT VERIFIED",
            "brew install nmap (or testssl.sh) if the engagement must "
            "evidence negotiated cipher suites")
    return CheckResult(chk.check_id, chk.name, PASS, detail)
