"""Intercepting-proxy CA trust bootstrap.

EXTRACTED CAPABILITY (CAP-040). Fetching the proxy's own CA certificate lets
the client verify the proxy strictly instead of disabling verification
entirely. The live-versus-on-disk fingerprint comparison catches a proxy that
has regenerated its CA, which otherwise shows up as confusing TLS failures.

The control endpoint is configuration, not a constant, because it differs
between proxy products.
"""
import os
import re
import subprocess

DEFAULT_CONTROL_URL = "http://proxy-control/cert"


def _run(cmd, timeout=30, input_bytes=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              input=input_bytes)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, b"", b"timeout"
    except OSError as exc:
        return 127, b"", str(exc).encode()


def fetch(proxy_url, control_url=DEFAULT_CONTROL_URL, out_path=None):
    """Fetch the proxy CA (DER) via the proxy and convert it to PEM."""
    rc, der, err = _run(["curl", "-sS", "--max-time", "15", "-x", proxy_url,
                         control_url])
    if rc != 0 or not der:
        return None, ("could not fetch the proxy CA from %s via %s: %s"
                      % (control_url, proxy_url,
                         err.decode("utf-8", "replace").strip()[:160]))
    rc2, pem, err2 = _run(["openssl", "x509", "-inform", "DER", "-outform",
                           "PEM"], input_bytes=der)
    if rc2 != 0 or b"BEGIN CERTIFICATE" not in pem:
        return None, ("fetched %d bytes but openssl could not parse it as a "
                      "DER certificate: %s"
                      % (len(der), err2.decode("utf-8", "replace")[:160]))
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "wb") as fh:
            fh.write(pem)
    return pem.decode("ascii", "replace"), None


def fingerprint_pem(pem_text_or_path):
    """SHA-256 fingerprint of a PEM certificate."""
    if os.path.exists(str(pem_text_or_path)):
        rc, out, err = _run(["openssl", "x509", "-in", str(pem_text_or_path),
                             "-noout", "-fingerprint", "-sha256"])
    else:
        rc, out, err = _run(["openssl", "x509", "-noout", "-fingerprint",
                             "-sha256"],
                            input_bytes=str(pem_text_or_path).encode())
    if rc != 0:
        return None
    m = re.search(r"=([0-9A-Fa-f:]+)", out.decode("utf-8", "replace"))
    return m.group(1) if m else None


def describe(pem_path):
    rc, out, _ = _run(["openssl", "x509", "-in", pem_path, "-noout",
                       "-subject", "-enddate"])
    return " ".join(out.decode("utf-8", "replace").split()) if rc == 0 else None


def compare(proxy_url, pem_path, control_url=DEFAULT_CONTROL_URL):
    """Compare the running proxy's CA against the one on disk.

    Returns (matches, detail). ``matches is None`` means undetermined.
    """
    live_pem, err = fetch(proxy_url, control_url)
    if live_pem is None:
        return None, err
    live = fingerprint_pem(live_pem)
    if not os.path.exists(pem_path):
        return None, "no CA on disk at %s (live fingerprint %s)" % (
            pem_path, (live or "?")[:24])
    disk = fingerprint_pem(pem_path)
    if not live or not disk:
        return None, "could not fingerprint one of the certificates"
    if live == disk:
        return True, "live and on-disk CA fingerprints match (%s)" % live[:24]
    return False, ("the proxy has regenerated its CA: live %s, on disk %s. "
                   "Re-fetch the CA." % (live[:24], disk[:24]))
