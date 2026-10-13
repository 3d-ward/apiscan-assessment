"""Engagement modes: offline review, limited live checks, active assessment.

ENGINEERING IMPROVEMENT (review finding: "make the default testing mode
genuinely conservative").

The framework previously had one live mode. A run either sent the corpus or it
did not, and the only thing standing between a careless invocation and a
production API was the scope policy -- which an operator in a hurry widens.
That is too coarse for the three genuinely different things an assessor does:

  OFFLINE_REVIEW  read the configuration, build the corpus, produce a test
                  plan a human can approve. Sends nothing, and cannot: the
                  mode is checked where the socket is opened, not only in the
                  command that chose it.

  LIMITED_LIVE    execute an explicitly named subset -- ids, families, phases
                  or a single endpoint -- under hard ceilings on case count,
                  wall-clock duration, response size and request rate. Classes
                  that can damage a target are refused outright, and NO
                  authorisation lifts that refusal: choosing a cautious mode
                  must not be overridable by a file the same operator edits.
                  This is the mode for a first contact with a live system.

  ACTIVE          mutation, injection, oversize bodies and volume, within the
                  agreed scope. Everything the scope policy authorises, and
                  nothing it does not.

The mode is deliberately not the scope policy. The policy records what the
client agreed to; the mode records how much of that the operator is exercising
right now. Both have to permit a request before it is sent, and the
intersection is what actually goes out.
"""
from ..core.errors import ScopeViolation
from .limits import RunLimits
from .scope import AGGRESSIVE_CLASSES

OFFLINE_REVIEW = "offline-review"
LIMITED_LIVE = "limited-live"
ACTIVE = "active"

ALL = (OFFLINE_REVIEW, LIMITED_LIVE, ACTIVE)

#: The default for any command that can send. A caller must name ACTIVE to get
#: the unrestricted behaviour, so an omitted flag is cautious rather than
#: maximal.
DEFAULT = LIMITED_LIVE


class Mode(object):
    """One engagement mode and the constraints that come with it."""

    def __init__(self, name, sends_traffic, requires_selection, hard_deny,
                 limits, summary):
        self.name = name
        self.sends_traffic = sends_traffic
        self.requires_selection = requires_selection
        #: Classes this mode refuses regardless of any recorded authorisation.
        self.hard_deny = frozenset(hard_deny)
        self.limits = limits
        self.summary = summary

    def assert_may_send(self):
        """Raise unless this mode permits traffic at all."""
        if not self.sends_traffic:
            raise ScopeViolation(
                "mode %r does not send traffic. It validates the "
                "configuration and produces a test plan for approval. Re-run "
                "with --mode %s to execute a named subset, or --mode %s for a "
                "full assessment within the agreed scope."
                % (self.name, LIMITED_LIVE, ACTIVE))
        return True

    def assert_selection(self, selectors):
        """Raise unless the caller named what to run, when the mode requires it.

        *selectors* is the dict of narrowing options the caller supplied
        (``ids``, ``families``, ``phases``, ``endpoint``). Limited live checks
        are explicitly-selected checks; a mode that silently ran the whole
        corpus when nobody named a subset would be the cautious mode in name
        only.
        """
        if not self.requires_selection:
            return True
        if any(selectors.get(k) for k in ("ids", "families", "phases",
                                          "endpoint")):
            return True
        raise ScopeViolation(
            "mode %r runs only explicitly selected checks, and none were "
            "named. Narrow the run with --ids, --families, --phases or "
            "--endpoint (use `generate --list` to choose), or state the "
            "intent explicitly with --mode %s."
            % (self.name, ACTIVE))

    def describe(self):
        parts = ["mode %s: %s" % (self.name, self.summary)]
        if self.hard_deny:
            parts.append("refused outright (no authorisation lifts these): %s"
                         % ", ".join(sorted(self.hard_deny)))
        if self.sends_traffic:
            parts.append(self.limits.describe())
        return "\n  ".join(parts)

    def as_dict(self):
        return {"mode": self.name, "sends_traffic": self.sends_traffic,
                "requires_selection": self.requires_selection,
                "hard_deny": sorted(self.hard_deny),
                "limits": self.limits.as_dict(), "summary": self.summary}

    def __repr__(self):
        return "<Mode %s>" % self.name


MODES = {
    OFFLINE_REVIEW: Mode(
        OFFLINE_REVIEW, sends_traffic=False, requires_selection=False,
        # Everything, so that a mode mix-up fails closed at the gate too.
        hard_deny=frozenset(AGGRESSIVE_CLASSES
                            | {"state_mutating", "malformed"}),
        limits=RunLimits(max_cases=0, max_duration_s=0),
        summary="validates configuration and produces a test plan; sends "
                "nothing"),
    LIMITED_LIVE: Mode(
        LIMITED_LIVE, sends_traffic=True, requires_selection=True,
        hard_deny=AGGRESSIVE_CLASSES,
        limits=RunLimits(max_cases=40, max_duration_s=600,
                         max_response_bytes=2 * 1024 * 1024,
                         min_delay_s=0.5, max_consecutive_server_errors=3,
                         max_consecutive_slow=5, slow_response_s=10.0),
        summary="executes an explicitly named subset under hard ceilings"),
    ACTIVE: Mode(
        ACTIVE, sends_traffic=True, requires_selection=False,
        hard_deny=frozenset(),
        limits=RunLimits(max_cases=5000, max_duration_s=7200,
                         max_response_bytes=16 * 1024 * 1024,
                         min_delay_s=0.0, max_consecutive_server_errors=10,
                         max_consecutive_slow=20, slow_response_s=30.0),
        summary="mutation, injection, oversize and volume within the agreed "
                "scope"),
}


def get(name):
    """Resolve a mode by name, with a message that lists the alternatives."""
    if name is None:
        return MODES[DEFAULT]
    if isinstance(name, Mode):
        return name
    try:
        return MODES[str(name)]
    except KeyError:
        raise ScopeViolation(
            "unknown mode %r; choose one of %s" % (name, ", ".join(ALL)))
