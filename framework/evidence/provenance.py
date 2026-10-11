"""Capture provenance.

EXTRACTED CAPABILITY (CAP-017), made structural.

The rule it encodes was learned the hard way: evidence that did not travel
through the intercepting proxy must not claim that it did. The specific trap is
transport-layer findings. An intercepting proxy terminates TLS and performs the
upstream handshake itself, presenting whatever client certificate it has been
configured with. So a "no client certificate was presented" test, sent through
the proxy, silently acquires one -- the rejection does not reproduce and the
request instead reaches the application. Such a finding can only be captured
directly, and its evidence must say so.

In the source this was a documented discipline plus a hand-overridden footer
string. Here the capture method is a required field that travels with every
evidence record into the filename, the footer and the report, so a mislabelled
artifact takes deliberate effort rather than forgetfulness.
"""


class CaptureMethod(object):
    """How an evidence artifact was produced."""

    PROXY = "proxy"
    DIRECT = "direct"
    PROXY_UI = "proxy-ui"
    DERIVED = "derived"
    DOCUMENT = "document"

    ALL = (PROXY, DIRECT, PROXY_UI, DERIVED, DOCUMENT)

    #: Methods whose evidence legitimately shows proxy-mediated traffic.
    VIA_PROXY = frozenset([PROXY, PROXY_UI])

    DESCRIPTIONS = {
        PROXY: "captured through the intercepting proxy; request and response "
               "bytes recorded verbatim by the client",
        DIRECT: "captured DIRECT, not through the proxy -- required for "
                "transport-layer evidence, which an intercepting proxy would "
                "alter by presenting its own client certificate",
        PROXY_UI: "screenshot of the proxy application window showing the "
                  "request and response panes",
        DERIVED: "rendered from previously captured bytes; no new traffic was "
                 "generated",
        DOCUMENT: "derived from supplied documentation rather than observed "
                  "traffic",
    }

    SUFFIXES = {
        PROXY: "proxy",
        DIRECT: "direct-transcript",
        PROXY_UI: "proxy-window",
        DERIVED: "rendered",
        DOCUMENT: "document",
    }


def validate(method):
    if method not in CaptureMethod.ALL:
        raise ValueError("unknown capture method %r (known: %s)"
                         % (method, ", ".join(CaptureMethod.ALL)))
    return method


def filename_suffix(method):
    """Suffix that makes the capture method visible in the filename itself."""
    return CaptureMethod.SUFFIXES[validate(method)]


def provenance_line(method, target_label, proxy_label=None, extra=None):
    """Build the footer asserting how this evidence was obtained.

    *target_label* and *proxy_label* are supplied by the caller -- there is no
    default, because a defaulted provenance string is exactly how evidence ends
    up asserting a capture path that did not happen.
    """
    validate(method)
    if method in CaptureMethod.VIA_PROXY:
        if not proxy_label:
            raise ValueError(
                "capture method %r asserts proxy mediation, so proxy_label is "
                "required" % method)
        line = "Captured via proxy %s" % proxy_label
    elif method == CaptureMethod.DIRECT:
        if proxy_label:
            raise ValueError(
                "capture method 'direct' must not carry a proxy_label; that "
                "would assert a capture path that did not happen")
        line = "Captured DIRECT (not via proxy)"
    elif method == CaptureMethod.DERIVED:
        line = "Rendered from previously captured bytes"
    else:
        line = "Derived from supplied documentation"

    line += " | target %s" % (target_label or "unspecified")
    # Only append the long description where it adds something the short form
    # does not already say; otherwise the footer repeats itself.
    description = CaptureMethod.DESCRIPTIONS[method]
    if method in (CaptureMethod.PROXY, CaptureMethod.DIRECT,
                  CaptureMethod.PROXY_UI):
        line += " | %s" % description
    if extra:
        line += " | %s" % extra
    return line
