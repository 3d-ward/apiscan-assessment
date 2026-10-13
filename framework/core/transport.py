"""HTTP transport over curl.

EXTRACTED CAPABILITY (CAP-001). curl is used rather than an HTTP library for
three reasons that matter to an assessment:

  * ``--trace-ascii`` records the wire exchange including the TLS handshake,
    which is the only way to evidence transport-layer findings;
  * ``--data-binary @file`` sends the body byte-for-byte, so control characters,
    lone surrogates and malformed JSON reach the target unaltered -- a library
    that re-encodes would quietly repair the very inputs under test;
  * requests route through an intercepting proxy identically to a browser, so
    the same traffic lands in proxy history for manual replay.

It also means the framework has no third-party runtime dependency for its core
loop.

Three properties of this module are safety properties, not conveniences:

1. **Nothing is sent without passing the scope gate.** A ``Transport`` cannot
   be constructed without a scope policy, and ``send`` refuses any request it
   cannot attribute to a permitted case or probe. The gate used to live in the
   runner, which meant every other caller -- preflight, fidelity, the
   rate-limit module -- reached the network around it.

2. **TLS verification is on unless the profile turns it off in writing.**
   A missing CA file is a hard failure, not a silent downgrade.

3. **Response headers and the response body are parsed from separate
   streams.** They used to share one, so a body containing a forged status
   line could rewrite the headers the oracle judged.
"""
import os
import re
import shutil
import subprocess

from . import headers as hdr
from .errors import ScopeViolation, TransportError
from .pathguard import safe_component

# A sentinel unlikely to appear in a response body, used to separate curl's
# -w metadata fields from each other.
SEP = "<<<APISCAN-SPLIT>>>"

_HTTP_START = re.compile(r"(?m)^HTTP/\d")

#: TLS verification modes a profile may declare.
TLS_SYSTEM = "system"      # verify against the host trust store (default)
TLS_CA = "ca"              # verify against a named CA bundle
TLS_INSECURE = "insecure"  # do not verify -- requires saying so explicitly
TLS_MODES = (TLS_SYSTEM, TLS_CA, TLS_INSECURE)


def split_last_response(blob):
    """Return (headers, body) for the LAST HTTP response in a header dump.

    EXTRACTED CAPABILITY (CAP-012) -- a correctness fix worth preserving
    exactly. Through a proxy, curl emits the proxy's own
    ``HTTP/1.1 200 Connection established`` block first. Splitting on the first
    blank line therefore returns the CONNECT headers and leaves the real
    response headers sitting at the top of what the caller believes is the body.
    Every header-based assertion downstream would then be wrong, and silently so.

    The same correction handles 1xx interim responses (``100 Continue``,
    ``103 Early Hints``).

    This is now applied to a header dump that contains ONLY headers. It was
    previously applied to headers and body concatenated, which made it an
    attack surface: see ``Transport.send``.
    """
    if not blob:
        return "", blob or ""
    starts = [m.start() for m in _HTTP_START.finditer(blob)]
    if not starts:
        return "", blob
    tail = blob[starts[-1]:]
    parts = re.split(r"\r?\n\r?\n", tail, maxsplit=1)
    return (parts[0], parts[1]) if len(parts) == 2 else (tail, "")


class Response(object):
    """One observed exchange. Carries everything the oracle needs."""

    def __init__(self, status, headers, body, meta):
        self.status = status
        self.headers = headers
        self.body = body
        self.meta = meta

    @property
    def ok_transport(self):
        return self.status not in ("000", "", None)

    @property
    def status_int(self):
        try:
            return int(self.status)
        except (TypeError, ValueError):
            return 0

    @property
    def truncated(self):
        return bool(self.meta.get("body_truncated"))

    def header(self, name):
        """First matching header value, case-insensitively, or None."""
        want = name.lower()
        for line in (self.headers or "").splitlines():
            if ":" in line and line.split(":", 1)[0].strip().lower() == want:
                return line.split(":", 1)[1].strip()
        return None

    def __repr__(self):
        return "<Response %s via=%s %dB%s>" % (
            self.status, self.meta.get("via", "?"), len(self.body or ""),
            " TRUNCATED" if self.truncated else "")


class Transport(object):
    """Issues requests described by a profile, gated by a scope policy.

    Holds no target constants: everything comes from the profile passed in.

    *scope_policy* is required. Passing ``None`` raises: there is no sensible
    default, because the only two candidates are "permit everything", which is
    how unauthorised traffic gets sent, and "permit nothing", which would turn
    a forgotten argument into a confusing empty run rather than a clear error.
    """

    def __init__(self, profile, auth_provider, body_dir, scope_policy=None,
                 via_proxy=True, curl="curl", limits=None, budget=None):
        if scope_policy is None:
            raise ScopeViolation(
                "Transport refuses to be constructed without a scope policy. "
                "Every request this framework sends passes one gate, so the "
                "policy belongs to the transport rather than to each caller. "
                "Pass scope_policy=ScopePolicy.load(<engagement "
                "scope-policy.json>), or ScopePolicy.default() for the "
                "default-deny policy.")
        self.profile = profile
        self.auth = auth_provider
        self.body_dir = body_dir
        self.scope = scope_policy
        self.via_proxy = via_proxy
        self.curl = curl
        self.limits = limits
        self.budget = budget
        os.makedirs(body_dir, exist_ok=True)
        #: curl writes the header dump and the body to separate files here.
        #: A subdirectory, so it never appears in the evidence manifest: the
        #: canonical record of a response is the evidence store's own file.
        self._scratch = os.path.join(body_dir, ".curl-scratch")
        os.makedirs(self._scratch, exist_ok=True)

    # -- scope -----------------------------------------------------------
    def _gate(self, probe, case_id, effective_proxy, today=None):
        """Refuse anything the engagement has not permitted.

        A caller that supplies no probe gets one that declares itself
        state-mutating and unclassified, which the default policy denies. That
        is deliberate: an unlabelled request is an unreviewed request.
        """
        from ..governance.scope import Probe
        if probe is None:
            probe = Probe(case_id, risk_classes=["unclassified_request"],
                          description="request issued without a declared "
                                      "case or probe")
        permitted, reason = self.scope.evaluate(probe, today,
                                                via_proxy=effective_proxy)
        if not permitted:
            raise ScopeViolation(
                "refusing to send %r: %s. Nothing was transmitted."
                % (getattr(probe, "id", case_id), reason))
        return reason

    # -- TLS -------------------------------------------------------------
    def tls_args(self):
        """curl arguments for certificate verification.

        ENGINEERING IMPROVEMENT (review finding: "enable HTTPS verification by
        default; stop when a configured CA file is missing").

        The previous behaviour was: use ``--cacert`` when a CA file is
        configured AND present, otherwise ``-k``. Both halves were wrong. An
        absent CA file -- a typo, a path that moved, a file never fetched --
        silently became an unverified connection, so the configuration that
        was supposed to make the run stricter made it weaker and said nothing.
        And a profile that simply omitted ``tls_verify`` got no verification
        at all by default.

        Now: verification is on; a declared CA must exist; and an unverified
        connection requires ``mode: "insecure"`` written in the profile.
        """
        verify = self.profile.transport.get("tls_verify") or {}
        mode = verify.get("mode") or TLS_SYSTEM
        ca_path = verify.get("ca_path")
        if mode not in TLS_MODES:
            raise TransportError(
                "transport.tls_verify.mode is %r; it must be one of %s"
                % (mode, ", ".join(TLS_MODES)))

        if mode == TLS_CA:
            if not ca_path:
                raise TransportError(
                    "transport.tls_verify.mode is 'ca' but no ca_path is "
                    "set. Name the CA bundle to verify against, or choose "
                    "mode 'system' to use the host trust store.")
            expanded = os.path.expanduser(str(ca_path))
            if not os.path.isfile(expanded):
                raise TransportError(
                    "the configured CA file does not exist: %s. Refusing to "
                    "continue: this used to fall back to an UNVERIFIED "
                    "connection, so a mistyped or moved CA path quietly "
                    "weakened every request in the run. Fetch the CA (for an "
                    "intercepting proxy, from its control endpoint), correct "
                    "transport.tls_verify.ca_path, or state mode 'insecure' "
                    "deliberately." % expanded)
            return ["--cacert", expanded]

        if mode == TLS_INSECURE:
            # Explicitly chosen in the profile, and recorded in run metadata
            # and the report so a deliverable cannot imply a verified path.
            args = ["-k"]
            if self.profile.proxy:
                args.append("--proxy-insecure")
            return args

        # TLS_SYSTEM: curl verifies by default; say nothing and let it.
        return []

    def tls_note(self):
        """Human-readable statement of the verification posture, for evidence."""
        verify = self.profile.transport.get("tls_verify") or {}
        mode = verify.get("mode") or TLS_SYSTEM
        if mode == TLS_CA:
            return "verified against %s" % verify.get("ca_path")
        if mode == TLS_INSECURE:
            return ("NOT VERIFIED -- transport.tls_verify.mode is 'insecure'; "
                    "certificate validity was not checked on this run")
        return "verified against the host trust store"

    # -- argument construction (pure, unit-testable) ---------------------
    def build_args(self, url, method="POST", identity=None, header_overrides=None,
                   content_type="application/json", body_file=None,
                   trace_file=None, use_proxy=None, header_file=None,
                   out_file=None):
        t = self.profile.transport
        use_proxy = self.via_proxy if use_proxy is None else use_proxy
        proxy = self.profile.proxy if use_proxy else None

        args = [self.curl, "-sS", "--max-time", str(t.get("timeout_s", 45)),
                "-w", SEP + "%{http_code}" + SEP + "%{time_total}"
                + SEP + "%{size_download}"]

        # Headers and body to SEPARATE destinations. See send().
        args += ["-D", header_file if header_file else "-"]
        args += ["-o", out_file if out_file else "-"]

        if proxy:
            args += ["-x", proxy]

        args += self.tls_args()

        cert = t.get("client_cert") or {}
        if cert.get("mode") == "direct" and cert.get("cert_path"):
            args += ["--cert", cert["cert_path"]]
            if cert.get("key_path"):
                args += ["--key", cert["key_path"]]
        # mode == "proxy": the certificate is configured inside the intercepting
        # proxy, because the proxy terminates TLS and performs the handshake.

        cap = self.max_response_bytes()
        if cap:
            # Refuse an oversized download rather than buffering it. Protects
            # the operator's disk and keeps one pathological endpoint from
            # consuming the whole run's budget.
            args += ["--max-filesize", str(cap)]

        args += ["-X", method]

        base_headers = self.auth.headers_for(identity) if self.auth else {}
        pairs = hdr.apply_overrides(base_headers, header_overrides)
        args += hdr.to_curl_args(pairs, content_type)
        # Suppress the 100-continue dance: it perturbs large-body tests and adds
        # an interim response that complicates header parsing.
        args += ["-H", "Expect:"]

        if trace_file:
            args += ["--trace-ascii", trace_file]
        if body_file is not None:
            args += ["--data-binary", "@" + body_file]

        args += list(t.get("extra_args") or [])
        args.append(url)
        return args

    def max_response_bytes(self):
        configured = self.profile.transport.get("max_response_bytes")
        from_limits = getattr(self.limits, "max_response_bytes", None)
        candidates = [c for c in (configured, from_limits) if c]
        return min(candidates) if candidates else 0

    # -- execution -------------------------------------------------------
    def send(self, case_id, url, method="POST", identity=None,
             header_overrides=None, content_type="application/json",
             body=None, trace_file=None, use_proxy=None, probe=None,
             today=None):
        """Issue one request and return a Response.

        *probe* is the case or ``governance.scope.Probe`` this request belongs
        to, and it is what the scope gate judges. It is optional only so that
        the failure is a clear refusal rather than a TypeError; an omitted
        probe is treated as unclassified and denied by the default policy.
        """
        safe_id = safe_component(case_id, what="case or probe id")
        effective_proxy = self.via_proxy if use_proxy is None else use_proxy
        scope_reason = self._gate(probe, safe_id, effective_proxy, today=today)

        if self.budget is not None:
            may, why = self.budget.check()
            if not may:
                raise TransportError(
                    "refusing to send %r: %s. Nothing was transmitted."
                    % (safe_id, why))

        body_file = None
        if body is not None:
            from .pathguard import safe_join
            body_file = safe_join(self.body_dir, "%s.req.txt" % safe_id,
                                  what="request body file")
            # surrogatepass keeps lone surrogates and control characters intact
            # on the way to disk; without it a malformed-input case is repaired
            # before it is ever sent.
            with open(body_file, "w", encoding="utf-8",
                      errors="surrogatepass") as fh:
                fh.write(body)
            _restrict(body_file)

        # ENGINEERING IMPROVEMENT (review finding: "separate response headers
        # from response bodies when collecting traffic").
        #
        # curl previously wrote both the header dump (-D -) and the body
        # (-o -) to stdout, and the two were separated afterwards by finding
        # the last line matching ^HTTP/\d. A response body is attacker- or
        # target-controlled data, so a body containing
        #
        #     HTTP/1.1 200 OK
        #     X-Anything: whatever
        #
        # relocated the split: everything before it was discarded as
        # "headers", and the forged lines became the headers the oracle
        # attributed, the detectors scanned and the verdict rested on. A
        # target could therefore choose its own classification.
        #
        # Two files, so the streams cannot be confused at all. The
        # last-response correction still applies, but now to a dump that
        # contains only headers.
        header_file = os.path.join(self._scratch, "%s.hdr" % safe_id)
        out_file = os.path.join(self._scratch, "%s.body" % safe_id)

        args = self.build_args(url, method=method, identity=identity,
                               header_overrides=header_overrides,
                               content_type=content_type, body_file=body_file,
                               trace_file=trace_file,
                               use_proxy=use_proxy,
                               header_file=header_file, out_file=out_file)
        try:
            proc = subprocess.run(args, capture_output=True, text=True,
                                  errors="replace")
        except OSError as exc:
            raise TransportError("cannot execute %s: %s" % (self.curl, exc))

        raw = proc.stdout or ""
        parts = raw.split(SEP)
        if len(parts) >= 4:
            status, elapsed, size = parts[1], parts[2], parts[3]
        else:
            status, elapsed, size = "000", "", ""

        header_dump = _read_text(header_file)
        body_text = _read_text(out_file)
        cap = self.max_response_bytes()
        truncated = False
        if cap and len(body_text.encode("utf-8", "replace")) > cap:
            body_text = body_text[:cap]
            truncated = True
        # curl --max-filesize aborts the transfer itself; record that too.
        if cap and "Maximum file size exceeded" in (proc.stderr or ""):
            truncated = True

        # The header dump contains only headers, so this split cannot be
        # moved by response content.
        headers, header_remainder = split_last_response(header_dump)
        _discard(header_file)
        _discard(out_file)

        meta = {
            "url": url,
            "method": method,
            "identity": identity or (self.auth.default_identity if self.auth else None),
            "via": self.profile.proxy if effective_proxy else "direct",
            "curl_rc": proc.returncode,
            "stderr": (proc.stderr or "").strip()[:400],
            "time_total": elapsed,
            "size_download": size,
            "request_file": body_file,
            "trace_file": trace_file,
            "scope_reason": scope_reason,
            "tls_verification": self.tls_note(),
            "body_truncated": truncated,
            "max_response_bytes": cap or None,
            "header_stream": "separate",
        }
        if header_remainder.strip():
            # Nothing should follow the headers in a header dump. If something
            # does, say so rather than folding it into either stream.
            meta["header_dump_remainder"] = header_remainder[:200]

        if self.budget is not None:
            self.budget.observe(status=status, elapsed_s=elapsed)

        return Response(status, headers, body_text, meta)


def _read_text(path):
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except (OSError, IOError):
        return ""


def _discard(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _restrict(path):
    """Owner-only permissions on a file that may carry client data."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def cleanup_scratch(body_dir):
    """Remove the curl scratch directory, if present."""
    scratch = os.path.join(body_dir, ".curl-scratch")
    if os.path.isdir(scratch):
        shutil.rmtree(scratch, ignore_errors=True)
