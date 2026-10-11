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
"""
import os
import re
import subprocess

from . import headers as hdr
from .errors import TransportError

# A sentinel unlikely to appear in a response body, used to separate curl's
# -w metadata from the payload.
SEP = "<<<APISCAN-SPLIT>>>"

_HTTP_START = re.compile(r"(?m)^HTTP/\d")


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

    def header(self, name):
        """First matching header value, case-insensitively, or None."""
        want = name.lower()
        for line in (self.headers or "").splitlines():
            if ":" in line and line.split(":", 1)[0].strip().lower() == want:
                return line.split(":", 1)[1].strip()
        return None

    def __repr__(self):
        return "<Response %s via=%s %dB>" % (
            self.status, self.meta.get("via", "?"), len(self.body or ""))


class Transport(object):
    """Issues requests described by a profile.

    Holds no target constants: everything comes from the profile passed in.
    """

    def __init__(self, profile, auth_provider, body_dir, via_proxy=True,
                 curl="curl"):
        self.profile = profile
        self.auth = auth_provider
        self.body_dir = body_dir
        self.via_proxy = via_proxy
        self.curl = curl
        os.makedirs(body_dir, exist_ok=True)

    # -- argument construction (pure, unit-testable) ---------------------
    def build_args(self, url, method="POST", identity=None, header_overrides=None,
                   content_type="application/json", body_file=None,
                   trace_file=None, use_proxy=None):
        t = self.profile.transport
        use_proxy = self.via_proxy if use_proxy is None else use_proxy
        proxy = self.profile.proxy if use_proxy else None

        args = [self.curl, "-sS", "--max-time", str(t.get("timeout_s", 45)),
                "-D", "-", "-o", "-",
                "-w", SEP + "%{http_code}" + SEP + "%{time_total}"
                + SEP + "%{size_download}"]

        if proxy:
            args += ["-x", proxy, "--proxy-insecure"]

        verify = t.get("tls_verify") or {}
        ca_path = verify.get("ca_path")
        if verify.get("mode") == "ca" and ca_path and os.path.exists(ca_path):
            args += ["--cacert", ca_path]
        else:
            # Interception terminates TLS, so strict verification of the target
            # certificate is not meaningful on the proxied path.
            args += ["-k"]

        cert = t.get("client_cert") or {}
        if cert.get("mode") == "direct" and cert.get("cert_path"):
            args += ["--cert", cert["cert_path"]]
            if cert.get("key_path"):
                args += ["--key", cert["key_path"]]
        # mode == "proxy": the certificate is configured inside the intercepting
        # proxy, because the proxy terminates TLS and performs the handshake.

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

    # -- execution -------------------------------------------------------
    def send(self, case_id, url, method="POST", identity=None,
             header_overrides=None, content_type="application/json",
             body=None, trace_file=None, use_proxy=None):
        """Issue one request and return a Response."""
        body_file = None
        if body is not None:
            body_file = os.path.join(self.body_dir, "%s.req.txt" % case_id)
            # surrogatepass keeps lone surrogates and control characters intact
            # on the way to disk; without it a malformed-input case is repaired
            # before it is ever sent.
            with open(body_file, "w", encoding="utf-8",
                      errors="surrogatepass") as fh:
                fh.write(body)

        args = self.build_args(url, method=method, identity=identity,
                               header_overrides=header_overrides,
                               content_type=content_type, body_file=body_file,
                               trace_file=trace_file, use_proxy=use_proxy)
        try:
            proc = subprocess.run(args, capture_output=True, text=True,
                                  errors="replace")
        except OSError as exc:
            raise TransportError("cannot execute %s: %s" % (self.curl, exc))

        raw = proc.stdout or ""
        parts = raw.split(SEP)
        if len(parts) >= 4:
            head_body, status, elapsed, size = parts[0], parts[1], parts[2], parts[3]
        else:
            head_body, status, elapsed, size = raw, "000", "", ""

        headers, body_text = split_last_response(head_body)
        meta = {
            "url": url,
            "method": method,
            "identity": identity or (self.auth.default_identity if self.auth else None),
            "via": self.profile.proxy if (use_proxy if use_proxy is not None
                                          else self.via_proxy) else "direct",
            "curl_rc": proc.returncode,
            "stderr": (proc.stderr or "").strip()[:400],
            "time_total": elapsed,
            "size_download": size,
            "request_file": body_file,
            "trace_file": trace_file,
        }
        return Response(status, headers, body_text, meta)
