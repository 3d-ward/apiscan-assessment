"""Proxy health guard.

EXTRACTED CAPABILITY (CAP-020).

The failure this prevents is specific and silent. If request interception is
toggled on -- which UI automation can do by accident -- every request queues
waiting to be forwarded. The client times out, the proxy records a history row
with no response attached, and any screenshot taken from that row shows an
EMPTY response pane. The resulting PoC looks plausible and evidences nothing.

So the proxy is checked BEFORE each capture rather than diagnosed afterwards,
and a failure aborts with the exact remedy while keeping images already taken.

ENGINEERING IMPROVEMENT: the source probed a third-party internet host, which
is unusable on an isolated network and quietly sends traffic off-box. This
version probes the proxy's own control endpoint by default and falls back to a
caller-supplied URL.
"""
import re
import subprocess
import time

DEFAULT_PROBE_URL = "http://proxy-control/"


class HealthResult(object):
    def __init__(self, healthy, detail, elapsed, remedy=""):
        self.healthy = healthy
        self.detail = detail
        self.elapsed = elapsed
        self.remedy = remedy

    def __bool__(self):
        return bool(self.healthy)

    def __repr__(self):
        return "<HealthResult %s %.2fs %s>" % (
            "healthy" if self.healthy else "UNHEALTHY", self.elapsed,
            self.detail[:50])


def check(proxy_url, probe_url=DEFAULT_PROBE_URL, budget=8):
    """True when the proxy forwards promptly rather than holding requests."""
    cmd = ["curl", "-sS", "--max-time", str(budget), "-x", proxy_url,
           "-o", "/dev/null", "-w", "%{http_code}", probe_url]
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=budget + 4)
        rc, out = proc.returncode, (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
    except subprocess.TimeoutExpired:
        rc, out, stderr = 124, "", "timed out"
    except OSError as exc:
        return HealthResult(False, "cannot execute curl: %s" % exc, 0.0)
    elapsed = time.time() - start

    if rc == 124 or elapsed >= budget - 0.5:
        return HealthResult(
            False,
            "a plain request through the proxy did not return within %.1fs"
            % elapsed, elapsed,
            "Request interception is almost certainly ON and holding the "
            "request. Turn interception off in the proxy, then re-run. Images "
            "captured before this point remain valid.")
    if rc != 0 and not re.match(r"^\d{3}$", out):
        return HealthResult(
            False, "proxy did not answer (rc=%s %s)" % (rc, stderr[:120]),
            elapsed,
            "Confirm the proxy is running and that its listener address "
            "matches %s." % proxy_url)
    return HealthResult(True, "forwarded in %.2fs (HTTP %s)"
                        % (elapsed, out or "n/a"), elapsed)


def require(proxy_url, probe_url=DEFAULT_PROBE_URL, budget=8):
    """Raise if the proxy is holding requests."""
    from framework.core.errors import TransportError
    result = check(proxy_url, probe_url, budget)
    if not result.healthy:
        raise TransportError("proxy is not forwarding: %s. %s"
                             % (result.detail, result.remedy))
    return result
