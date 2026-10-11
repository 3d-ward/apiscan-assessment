import unittest

from tests.support import FakeResponse, ROOT  # noqa: F401
from framework.oracle import envelope as E
from framework.oracle import layers as L
from framework.oracle import verdict as V

MODEL = {
    "status_layers": {},
    "envelope": {"code_path": "resultCode", "remark_path": "resultMessage",
                 "data_path": "errors", "success_values": ["0000"],
                 "auth_failure_values": ["0401"]},
    "edge_block_markers": ["No required SSL certificate was sent"],
    "business_markers": ["Record Not Found"],
}


class TestEnvelope(unittest.TestCase):
    SPEC = {"code_path": "status.code", "remark_path": "status.message",
            "data_path": "errors", "success_values": ["0"]}

    def test_nested_path(self):
        r = E.decode('{"status":{"code":"0","message":"ok"}}', self.SPEC)
        self.assertTrue(r.present)
        self.assertEqual(r.code, "0")
        self.assertEqual(r.source, "json")
        self.assertTrue(E.is_success(r, self.SPEC))

    def test_data_is_appended_to_detail(self):
        r = E.decode('{"status":{"code":"4","message":"bad"},'
                     '"errors":["x"]}', self.SPEC)
        self.assertIn("x", r.detail)

    def test_malformed_body_falls_back_to_regex(self):
        r = E.decode('{"status":{"code":"7","message":"nope"', self.SPEC)
        self.assertTrue(r.present)
        self.assertEqual(r.source, "regex")

    def test_absent_cases(self):
        self.assertFalse(E.decode("", self.SPEC).present)
        self.assertFalse(E.decode('{"a":1}', None).present)
        self.assertFalse(E.decode('{"other":1}', self.SPEC).present)


class TestLayerAttribution(unittest.TestCase):
    def attribute(self, status, body=""):
        return L.attribute(FakeResponse(status, body), MODEL)

    def test_edge_block_precedes_everything(self):
        a = self.attribute(400, "400 No required SSL certificate was sent")
        self.assertEqual(a.layer, L.EDGE_BLOCK)

    def test_transport_error(self):
        a = L.attribute(FakeResponse("000", meta={"stderr": "refused"}), MODEL)
        self.assertEqual(a.layer, L.TRANSPORT_ERROR)

    def test_status_mapping(self):
        for status, layer in ((400, "validation_reject"), (401, "auth_reject"),
                              (403, "auth_reject"), (405, "method_reject"),
                              (413, "edge_reject"), (415, "ctype_reject"),
                              (500, "server_error")):
            self.assertEqual(self.attribute(status).layer, layer, status)

    def test_envelope_refines_a_200(self):
        self.assertEqual(
            self.attribute(200, '{"resultCode":"0000"}').layer,
            "accepted_success")
        self.assertEqual(
            self.attribute(200, '{"resultCode":"0400","resultMessage":"bad"}'
                           ).layer, "business_reject")
        self.assertEqual(
            self.attribute(200, '{"resultCode":"0401"}').layer, "auth_reject")

    def test_404_needs_a_business_marker_to_mean_record_absent(self):
        self.assertEqual(self.attribute(404, "nothing").layer, "route_404")
        self.assertEqual(
            self.attribute(404, '{"resultMessage":"Record Not Found"}').layer,
            "business_reject")

    def test_a_mapped_rejection_status_is_not_overridden_by_the_envelope(self):
        # An edge component can refuse before the application writes an
        # envelope, so a 413 stays an edge rejection.
        self.assertEqual(self.attribute(413, '{"resultCode":"0000"}').layer,
                         "edge_reject")


class TestVerdict(unittest.TestCase):
    def decide(self, expectation, status, body="", **kw):
        a = L.attribute(FakeResponse(status, body), MODEL)
        return V.decide(expectation, a, **kw)

    def test_full_matrix_reject(self):
        cases = {
            400: V.CONTROL_PRESENT, 401: V.CONTROL_PRESENT,
            405: V.CONTROL_PRESENT, 413: V.CONTROL_PRESENT,
            415: V.CONTROL_PRESENT, 409: V.CONTROL_PRESENT,
            500: V.ERROR,
        }
        for status, expected in cases.items():
            self.assertEqual(self.decide("reject", status).verdict, expected,
                             status)
        self.assertEqual(
            self.decide("reject", 200, '{"resultCode":"0000"}').verdict,
            V.CONTROL_ABSENT)

    def test_full_matrix_accept(self):
        self.assertEqual(
            self.decide("accept", 200, '{"resultCode":"0000"}').verdict,
            V.CONTROL_PRESENT)
        for status in (400, 401, 405, 413, 415):
            self.assertEqual(self.decide("accept", status).verdict,
                             V.OVER_BLOCKED, status)

    def test_blocked_is_never_a_pass_or_a_failure(self):
        for expectation in ("reject", "accept", "observe"):
            d = self.decide(expectation, 400,
                            "400 No required SSL certificate was sent")
            self.assertEqual(d.verdict, V.BLOCKED, expectation)

    def test_observe_never_passes_or_fails(self):
        self.assertEqual(self.decide("observe", 200,
                                     '{"resultCode":"0000"}').verdict,
                         V.OBSERVED)

    def test_route_404_is_unclear_not_a_pass(self):
        self.assertEqual(self.decide("reject", 404, "nope").verdict, V.UNCLEAR)

    def test_control_depth_is_recorded(self):
        self.assertEqual(self.decide("reject", 400).control_depth,
                         "pre-business")
        self.assertEqual(self.decide("reject", 409).control_depth, "business")

    def test_policy_difference_is_explicit_and_bounded(self):
        """The layered/validation_strict divergence is intentional and must
        occur at exactly one layer."""
        divergent = []
        for status in (400, 401, 405, 409, 413, 415):
            layered = self.decide("reject", status).verdict
            strict = self.decide("reject", status,
                                 policy="validation_strict").verdict
            if layered != strict:
                divergent.append(status)
        self.assertEqual(divergent, [409])

    def test_shallow_reject_required_demands_a_pre_business_control(self):
        d = self.decide("reject", 409, shallow_reject_required=True)
        self.assertEqual(d.verdict, V.CONTROL_ABSENT)

    def test_unknown_inputs_raise(self):
        a = L.attribute(FakeResponse(200), MODEL)
        with self.assertRaises(ValueError):
            V.decide("maybe", a)
        with self.assertRaises(ValueError):
            V.decide("reject", a, policy="nonsense")


if __name__ == "__main__":
    unittest.main()
