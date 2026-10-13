"""Run ceilings and stop conditions.

ENGINEERING IMPROVEMENT (review finding: "add maximum duration, response-size
limits, and stop conditions for repeated server errors or excessive latency").

A scope policy decides whether a request is permitted. It says nothing about
how long a run may take, how much it may download, or what should happen when
the target starts failing -- and those are the properties that decide whether
an assessment degrades into an outage. A target that has begun answering 500
to everything is no longer being measured; continuing to send is both useless
as evidence and the most likely way an assessment causes the incident it was
meant to prevent.

So a run carries a budget. It is checked before each case and updated after
each response, and when it trips the remaining cases are recorded as skipped
with the reason -- never silently dropped, because coverage accounting has to
show that the run stopped early and why.
"""
import time


class RunLimits(object):
    """Declarative ceilings for one run."""

    def __init__(self, max_cases=5000, max_duration_s=7200,
                 max_response_bytes=16 * 1024 * 1024, min_delay_s=0.0,
                 max_consecutive_server_errors=10, max_consecutive_slow=20,
                 slow_response_s=30.0):
        self.max_cases = int(max_cases)
        self.max_duration_s = float(max_duration_s)
        self.max_response_bytes = int(max_response_bytes)
        self.min_delay_s = float(min_delay_s)
        self.max_consecutive_server_errors = int(max_consecutive_server_errors)
        self.max_consecutive_slow = int(max_consecutive_slow)
        self.slow_response_s = float(slow_response_s)

    def replace(self, **kw):
        """A copy with named ceilings overridden, each only ever TIGHTENED.

        An operator may ask for less than the mode allows; asking for more is
        refused silently-but-visibly by clamping, so a `--max-cases 10000`
        against a limited-live run does not quietly become the active mode.
        """
        values = self.as_dict()
        for key, value in kw.items():
            if value is None or key not in values:
                continue
            if key in ("min_delay_s",):
                values[key] = max(values[key], float(value))
            elif key in ("slow_response_s",):
                values[key] = min(values[key], float(value))
            else:
                values[key] = min(values[key], type(values[key])(value))
        return RunLimits(**values)

    def as_dict(self):
        return {
            "max_cases": self.max_cases,
            "max_duration_s": self.max_duration_s,
            "max_response_bytes": self.max_response_bytes,
            "min_delay_s": self.min_delay_s,
            "max_consecutive_server_errors":
                self.max_consecutive_server_errors,
            "max_consecutive_slow": self.max_consecutive_slow,
            "slow_response_s": self.slow_response_s,
        }

    def describe(self):
        return ("ceilings: %d case(s), %.0fs wall clock, %.1f MB per "
                "response, %.2fs between requests; stop after %d consecutive "
                "server errors or %d consecutive responses slower than %.0fs"
                % (self.max_cases, self.max_duration_s,
                   self.max_response_bytes / 1048576.0, self.min_delay_s,
                   self.max_consecutive_server_errors,
                   self.max_consecutive_slow, self.slow_response_s))


class Budget(object):
    """Tracks a run against its limits and reports when it must stop."""

    def __init__(self, limits, clock=None):
        self.limits = limits
        self.clock = clock or time.time
        self.started = None
        self.sent = 0
        self.consecutive_server_errors = 0
        self.consecutive_slow = 0
        self.stopped_reason = None

    def start(self):
        self.started = self.clock()
        return self

    @property
    def elapsed(self):
        return 0.0 if self.started is None else self.clock() - self.started

    def check(self):
        """(may_continue, reason). Called before each case is sent."""
        if self.stopped_reason:
            return False, self.stopped_reason
        if self.started is None:
            self.start()
        if self.sent >= self.limits.max_cases:
            return self._stop(
                "run ceiling reached: %d case(s) sent, which is this mode's "
                "maximum. Narrow the selection or raise the mode."
                % self.limits.max_cases)
        if self.limits.max_duration_s and \
                self.elapsed >= self.limits.max_duration_s:
            return self._stop(
                "run ceiling reached: %.0fs elapsed, which is this mode's "
                "maximum duration" % self.elapsed)
        return True, None

    def observe(self, status=None, elapsed_s=None):
        """Update the stop conditions from one observed response."""
        self.sent += 1
        code = 0
        try:
            code = int(status)
        except (TypeError, ValueError):
            code = 0
        if code >= 500 or code == 0:
            self.consecutive_server_errors += 1
        else:
            self.consecutive_server_errors = 0
        try:
            took = float(elapsed_s)
        except (TypeError, ValueError):
            took = 0.0
        if took and took >= self.limits.slow_response_s:
            self.consecutive_slow += 1
        else:
            self.consecutive_slow = 0

        if self.consecutive_server_errors >= \
                self.limits.max_consecutive_server_errors:
            self._stop(
                "stop condition: %d consecutive server errors or transport "
                "failures. The target is no longer answering usefully, so "
                "further requests would produce no evidence and risk making "
                "it worse. Investigate before resuming."
                % self.consecutive_server_errors)
        elif self.consecutive_slow >= self.limits.max_consecutive_slow:
            self._stop(
                "stop condition: %d consecutive responses slower than %.0fs. "
                "The target appears to be degrading under the assessment."
                % (self.consecutive_slow, self.limits.slow_response_s))
        return self.stopped_reason

    def _stop(self, reason):
        self.stopped_reason = reason
        return False, reason

    def as_dict(self):
        return {"limits": self.limits.as_dict(), "sent": self.sent,
                "elapsed_s": round(self.elapsed, 2),
                "stopped_reason": self.stopped_reason}
