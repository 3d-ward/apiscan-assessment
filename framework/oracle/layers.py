"""Layer attribution -- which layer of the stack answered this request?

EXTRACTED CAPABILITY (CAP-006), the analytic core of the toolkit.

The governing idea is that an HTTP status code is not a verdict. "400" might be
an edge size limit, a media-type refusal or application validation; "200" might
be an acceptance or an application-level rejection carried in the body. What an
assessor actually needs to know is *which layer refused the request*, because
that is what says whether a control exists and how deep it sits.

Attribution precedence, in order, each step documented where it is not obvious:

  1. transport failure      -- no response at all
  2. edge block             -- a pre-application control refused the connection
  3. mapped HTTP status     -- the profile's status_layers table
  4. envelope refinement    -- for APIs that answer 200 and signal in the body
  5. business markers       -- distinguish "route absent" from "record absent"

Step 2 precedes everything because a request stopped before the application was
never actually tested; recording it as anything other than blocked would count
an unreached test as a result. See ``verdict.BLOCKED``.
"""
import re

from . import envelope as env

# Layers that are derived from observation rather than mapped from a status.
TRANSPORT_ERROR = "transport_error"
EDGE_BLOCK = "edge_block"

# Layers at which a request was refused. Attribution only -- whether a refusal
# is the *right* outcome is decided in verdict.py.
REJECT_LAYERS = frozenset([
    "edge_reject", "auth_reject", "method_reject", "ctype_reject",
    "validation_reject", "business_reject",
])
# Layers meaning the request was carried out or reached application logic.
REACHED_LAYERS = frozenset(["business_reached", "accepted_success"])

ERROR_LAYERS = frozenset([TRANSPORT_ERROR, "server_error"])

DEFAULT_STATUS_LAYERS = {
    "400": "validation_reject",
    "401": "auth_reject",
    "403": "auth_reject",
    "404": "route_404",
    "405": "method_reject",
    "409": "business_reject",
    "413": "edge_reject",
    "414": "edge_reject",
    "415": "ctype_reject",
    "429": "edge_reject",
    "431": "edge_reject",
    "2xx": "accepted_success",
    "5xx": "server_error",
    "default": "other",
}


class Attribution(object):
    """The result of attributing one response to a layer."""

    def __init__(self, layer, remark="", envelope=None, basis="", status=None):
        self.layer = layer
        self.remark = remark
        self.envelope = envelope
        self.basis = basis          # why this layer was chosen
        self.status = status

    @property
    def is_reject(self):
        return self.layer in REJECT_LAYERS

    @property
    def is_reached(self):
        return self.layer in REACHED_LAYERS

    @property
    def is_error(self):
        return self.layer in ERROR_LAYERS

    @property
    def is_blocked(self):
        return self.layer == EDGE_BLOCK

    def __repr__(self):
        return "<Attribution %s (%s) remark=%r>" % (self.layer, self.basis,
                                                    self.remark[:40])


def _map_status(status_int, table):
    """Exact code, then Nxx class, then default."""
    code = str(status_int)
    if code in table:
        return table[code], "status %s mapped" % code
    klass = "%sxx" % code[0] if code and code[0].isdigit() else None
    if klass and klass in table:
        return table[klass], "status class %s mapped" % klass
    if "default" in table:
        return table["default"], "status default mapping"
    return "other", "status %s unmapped" % code


def attribute(response, response_model):
    """Attribute *response* to the layer that answered it."""
    model = response_model or {}
    table = dict(DEFAULT_STATUS_LAYERS)
    table.update(model.get("status_layers") or {})
    env_spec = model.get("envelope")
    body = response.body or ""
    status = response.status

    # 1. transport failure -- nothing was observed, so nothing was tested.
    if not response.ok_transport:
        detail = response.meta.get("stderr") or "no response"
        return Attribution(TRANSPORT_ERROR, detail, None,
                           "no HTTP response", status)

    # 2. edge block -- a control in front of the application refused us.
    for marker in (model.get("edge_block_markers") or []):
        if marker and marker in body:
            return Attribution(EDGE_BLOCK, marker, None,
                               "edge_block_marker matched", status)

    code = response.status_int
    layer, basis = _map_status(code, table)

    decoded = env.decode(body, env_spec) if env_spec else env.ABSENT
    remark = decoded.detail if decoded.present else ""

    # 3/4. Envelope refinement. Only applied where the HTTP status is not
    # itself decisive: a mapped rejection status is trusted, because an edge
    # component may refuse a request before the application ever writes an
    # envelope.
    if decoded.present and layer in ("accepted_success", "business_reached",
                                     "other", "route_404"):
        if env.is_auth_failure(decoded, env_spec):
            return Attribution("auth_reject", remark, decoded,
                               "envelope auth-failure code %s" % decoded.code,
                               status)
        if env.is_success(decoded, env_spec):
            return Attribution("accepted_success", remark, decoded,
                               "envelope success code %s" % decoded.code, status)
        # Envelope present and not a success code: the application received the
        # request and refused it. That is a refusal at business level, not an
        # acceptance -- scoring it as accepted is the mistake this refinement
        # exists to prevent.
        return Attribution("business_reject", remark, decoded,
                           "envelope non-success code %s" % decoded.code, status)

    # 5. business markers -- separate "no such route" from "no such record".
    #
    # Note the interaction with step 4: a 404 that carries the application's
    # OWN envelope has already been refined above, because writing an envelope
    # means the application handled the request and the route therefore exists.
    # The source attributed every envelope-bearing 404 to route_404, which
    # pushed it to UNCLEAR and discarded that information. This is intentional
    # divergence #2 and is pinned by
    # tests/regression/test_oracle_differential.py.
    if layer == "route_404":
        low = body.lower()
        hits = [m for m in (model.get("business_markers") or [])
                if m and m.lower() in low]
        if hits or remark:
            return Attribution("business_reject", remark or hits[0], decoded,
                               "404 with business marker", status)
        return Attribution("route_404", remark, decoded,
                           "404 with no business marker", status)

    return Attribution(layer, remark, decoded, basis, status)
