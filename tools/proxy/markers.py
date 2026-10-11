"""Deterministic proxy-history correlation.

EXTRACTED CAPABILITY (CAP-015).

A proxy's HTTP-history search matches the URL, not the request body. So a body
string -- the very thing that distinguishes one tamper case from another --
cannot be used to find a case's row. Appending a unique marker to the query
string makes the filtered history exactly one row, which is what makes row
selection deterministic.

Two things the source established and this preserves:

  * Relying on "history is sorted newest-first" is NOT safe. Sort order is a
    user setting; in the source project it was ascending by time, so an
    unfiltered row 1 was the OLDEST request in the table.
  * Markers are OFF by default. A marker changes the request, so a PoC taken
    with one is not byte-identical to the request that produced the finding.
    Enable them deliberately, and only after confirming the extra parameter is
    behaviourally inert against the target.

ENGINEERING IMPROVEMENT: a header-based marker, for targets that validate or
reject unknown query parameters (which an API with strict input validation --
exactly the kind worth testing -- may well do).
"""
import secrets
from urllib.parse import urlencode, urlparse, urlunparse

DEFAULT_PARAM = "apiscase"
DEFAULT_HEADER = "X-APIScan-Case"


def token(case_id, entropy_bytes=3):
    """A marker unique to this capture attempt.

    The random prefix matters: re-running a case would otherwise produce two
    history rows with the same marker, and the filter would again be ambiguous.
    """
    return "%s-%s" % (secrets.token_hex(entropy_bytes), case_id)


def apply_query(url, marker, param=DEFAULT_PARAM):
    """Append ``?<param>=<marker>`` to *url*, preserving any existing query."""
    parts = urlparse(url)
    query = parts.query
    extra = urlencode({param: marker})
    combined = "%s&%s" % (query, extra) if query else extra
    return urlunparse(parts._replace(query=combined))


def apply_header(marker, header=DEFAULT_HEADER):
    return {header: marker}


def search_string(marker, param=DEFAULT_PARAM, mode="query"):
    """What to type into the proxy's history filter to isolate this row."""
    if mode == "query":
        return "%s=%s" % (param, marker)
    return marker


class MarkerPolicy(object):
    """How a run marks requests for later correlation."""

    def __init__(self, enabled=False, mode="query", param=DEFAULT_PARAM,
                 header=DEFAULT_HEADER, inertness_confirmed=False):
        if mode not in ("query", "header"):
            raise ValueError("marker mode must be 'query' or 'header'")
        self.enabled = enabled
        self.mode = mode
        self.param = param
        self.header = header
        self.inertness_confirmed = inertness_confirmed

    def caveat(self):
        if not self.enabled:
            return ("markers disabled: requests are byte-identical to the "
                    "originals, and history rows must be correlated by "
                    "re-sending under a marker at capture time")
        base = ("markers enabled in %s mode: each request carries %r, so "
                "history filters to exactly one row"
                % (self.mode,
                   self.param if self.mode == "query" else self.header))
        if not self.inertness_confirmed:
            base += (". NOT YET CONFIRMED behaviourally inert against this "
                     "target -- verify before relying on results, since a "
                     "strict API may reject the extra parameter and every "
                     "case would then fail for the wrong reason")
        return base

    def decorate(self, url, case_id):
        """Return (url, header_overrides, search_string)."""
        if not self.enabled:
            return url, {}, None
        mark = token(case_id)
        if self.mode == "query":
            return (apply_query(url, mark, self.param), {},
                    search_string(mark, self.param, "query"))
        return url, apply_header(mark, self.header), \
            search_string(mark, mode="header")
