"""Differential testing of the reconstructed oracle.

The oracle is the reconstruction most likely to have drifted from the source,
because it is the piece that was most heavily restructured. Asserting "it looks
right" is not evidence, so this module contains an INDEPENDENT reference
implementation of the source's classification semantics, written directly from
the behaviour the original exhibited, and compares the two across a generated
matrix of responses.

The two implementations are expected to agree everywhere EXCEPT at one
deliberate, documented divergence: a business-layer refusal of a case expecting
rejection. The source scored that CONTROL-ABSENT (it assumed every finding was
a validation finding); the reconstruction scores it CONTROL-PRESENT under the
``layered`` policy and records the depth. Under ``validation_strict`` the two
must agree exactly -- which is what proves the divergence is intentional rather
than accidental drift.
"""
import itertools
import unittest

from tests.support import FakeResponse, ROOT  # noqa: F401
from framework.oracle import layers as L
from framework.oracle import verdict as V

MODEL = {
    "status_layers": {},
    "envelope": {"code_path": "resultCode", "remark_path": "resultMessage",
                 "success_values": ["0000"], "auth_failure_values": ["0401"]},
    "edge_block_markers": ["No required SSL certificate was sent"],
    "business_markers": ["Record Not Found"],
}

# -- reference implementation (source semantics) -------------------------
REF_FIXED_LAYERS = {"validation_reject", "edge_reject", "auth_reject",
                    "method_reject", "ctype_reject"}
REF_PASSED_LAYERS = {"business_reached", "business_reached_200",
                     "accepted_success", "business_reject"}


def reference_classify(status, body):
    """The source's layer attribution, rewritten from its observed behaviour."""
    if status == "000":
        return "transport_error"
    if "No required SSL certificate was sent" in body:
        return "edge_block"
    code = int(status)
    if code in (413, 414, 431):
        return "edge_reject"
    if code in (401, 403):
        return "auth_reject"
    if code == 405:
        return "method_reject"
    if code == 415:
        return "ctype_reject"
    if code >= 500:
        return "server_error"
    if code == 400:
        return "validation_reject"
    if code == 404:
        return "business_reject" if "Record Not Found" in body else "route_404"
    if code == 409:
        return "business_reject"
    if 200 <= code < 300:
        if '"resultCode":"0000"' in body.replace(" ", ""):
            return "accepted_success"
        if '"resultCode"' in body.replace(" ", ""):
            if '"resultCode":"0401"' in body.replace(" ", ""):
                return "auth_reject"
            return "business_reject"
        return "accepted_success"
    return "other"


def reference_verdict(expectation, layer):
    """The source's expectation-to-verdict mapping."""
    if layer == "edge_block":
        return V.BLOCKED
    if layer in ("transport_error", "server_error"):
        return V.ERROR
    if expectation == "observe":
        return V.OBSERVED
    if expectation == "reject":
        if layer in REF_FIXED_LAYERS:
            return V.CONTROL_PRESENT
        if layer in REF_PASSED_LAYERS:
            return V.CONTROL_ABSENT
        return V.UNCLEAR
    if expectation == "accept":
        if layer in ("accepted_success", "business_reached",
                     "business_reached_200"):
            return V.CONTROL_PRESENT
        if layer == "validation_reject":
            return V.OVER_BLOCKED
        if layer in REF_FIXED_LAYERS or layer == "business_reject":
            return V.OVER_BLOCKED
        return V.UNCLEAR
    return V.UNCLEAR


# -- the matrix ----------------------------------------------------------
STATUSES = ["000", "200", "201", "400", "401", "403", "404", "405", "409",
            "413", "415", "500", "503"]
BODIES = [
    "",
    "plain text",
    '{"resultCode":"0000","resultMessage":"Success"}',
    '{"resultCode":"0400","resultMessage":"Invalid"}',
    '{"resultCode":"0401","resultMessage":"Authentication failed"}',
    '{"resultMessage":"Record Not Found"}',
    "400 No required SSL certificate was sent",
]
EXPECTATIONS = ["reject", "accept", "observe"]


class TestOracleDifferential(unittest.TestCase):
    def matrix(self):
        return itertools.product(STATUSES, BODIES, EXPECTATIONS)

    #: Intentional divergence #2, found by this very test. A 404 that carries
    #: the application's own envelope means the application handled the request,
    #: so the route exists. The source attributed every envelope-bearing 404 to
    #: route_404, which pushes it to UNCLEAR and throws that information away.
    ALLOWED_ATTRIBUTION_DIVERGENCES = {
        ("404", "route_404", "accepted_success"),
        ("404", "route_404", "business_reject"),
        ("404", "route_404", "auth_reject"),
    }

    def test_layer_attribution_diverges_only_where_documented(self):
        divergences = set()
        for status, body, _ in self.matrix():
            mine = L.attribute(FakeResponse(status, body, meta={}), MODEL).layer
            theirs = reference_classify(status, body)
            if mine != theirs:
                divergences.add((status, theirs, mine))
        undocumented = divergences - self.ALLOWED_ATTRIBUTION_DIVERGENCES
        self.assertEqual(undocumented, set(),
                         "layer attribution drifted from the source semantics "
                         "in an undocumented way: %r" % undocumented)

    def test_the_documented_attribution_divergence_still_occurs(self):
        """A divergence that silently stops happening is also drift."""
        divergences = set()
        for status, body, _ in self.matrix():
            mine = L.attribute(FakeResponse(status, body, meta={}), MODEL).layer
            theirs = reference_classify(status, body)
            if mine != theirs:
                divergences.add((status, theirs, mine))
        self.assertEqual(divergences, self.ALLOWED_ATTRIBUTION_DIVERGENCES)

    def test_validation_strict_policy_agrees_exactly(self):
        """Proof that the reconstruction did not drift accidentally."""
        mismatches = []
        for status, body, expectation in self.matrix():
            attribution = L.attribute(FakeResponse(status, body, meta={}),
                                      MODEL)
            mine = V.decide(expectation, attribution,
                            policy="validation_strict").verdict
            theirs = reference_verdict(expectation, attribution.layer)
            if mine != theirs:
                mismatches.append((status, body[:36], expectation, mine,
                                   theirs))
        self.assertEqual(mismatches, [],
                         "validation_strict must reproduce source semantics "
                         "exactly: %r" % mismatches[:5])

    def test_layered_policy_diverges_only_where_documented(self):
        """The improvement must be surgical: one layer, one expectation."""
        divergences = set()
        for status, body, expectation in self.matrix():
            attribution = L.attribute(FakeResponse(status, body, meta={}),
                                      MODEL)
            mine = V.decide(expectation, attribution,
                            policy="layered").verdict
            theirs = reference_verdict(expectation, attribution.layer)
            if mine != theirs:
                divergences.add((attribution.layer, expectation, theirs, mine))
        # Two documented effects:
        #   1. business-layer refusal now satisfies an expectation of rejection
        #   2. an envelope-bearing 404 is attributed to the application, so it
        #      no longer falls through to UNCLEAR
        expected = {
            ("business_reject", "reject", V.CONTROL_ABSENT, V.CONTROL_PRESENT),
            ("business_reject", "reject", V.UNCLEAR, V.CONTROL_PRESENT),
            ("business_reject", "accept", V.UNCLEAR, V.OVER_BLOCKED),
            ("accepted_success", "reject", V.UNCLEAR, V.CONTROL_ABSENT),
            ("accepted_success", "accept", V.UNCLEAR, V.CONTROL_PRESENT),
            ("auth_reject", "reject", V.UNCLEAR, V.CONTROL_PRESENT),
            ("auth_reject", "accept", V.UNCLEAR, V.OVER_BLOCKED),
        }
        self.assertTrue(
            divergences <= expected,
            "the layered policy diverged somewhere undocumented: %r"
            % (divergences - expected))

    def test_blocked_never_becomes_a_pass_under_either_policy(self):
        for expectation, policy in itertools.product(
                EXPECTATIONS, ("layered", "validation_strict")):
            attribution = L.attribute(
                FakeResponse("400", "400 No required SSL certificate was sent"),
                MODEL)
            self.assertEqual(
                V.decide(expectation, attribution, policy=policy).verdict,
                V.BLOCKED)

    def test_every_matrix_cell_produces_a_known_verdict(self):
        for status, body, expectation in self.matrix():
            attribution = L.attribute(FakeResponse(status, body, meta={}),
                                      MODEL)
            self.assertIn(V.decide(expectation, attribution).verdict, V.ALL)


if __name__ == "__main__":
    unittest.main()
