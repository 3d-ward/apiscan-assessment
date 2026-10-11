"""Transport-layer probes must pass the same scope gate as corpus cases.

ENGINEERING IMPROVEMENT. ``framework/modules/tls_posture`` opens sockets to the
client's edge, but had no CLI surface and was called directly in Python, so it
never reached ``ScopePolicy.filter``. It was the one module whose traffic the
engagement's rules of engagement could not govern. These tests pin the gate
shut: no policy, no packet.

Nothing here sends traffic off the host -- the permitted paths point at a
closed loopback port, which curl refuses immediately.
"""
import unittest

from tests.support import ROOT  # noqa: F401
from framework.core.errors import AuthorisationError
from framework.governance.scope import ScopePolicy, TransportProbe
from framework.modules import tls_posture

CLOSED = "https://127.0.0.1:1/"


def policy(**over):
    spec = {"schema": "scope-policy/1", "deny_classes": []}
    spec.update(over)
    return ScopePolicy(spec)


class TestTransportProbeAttributes(unittest.TestCase):
    def test_a_probe_does_not_mutate_state(self):
        self.assertFalse(TransportProbe("tls").state_mutating)

    def test_a_probe_carries_its_own_risk_class(self):
        self.assertIn("transport_probe", TransportProbe("tls").risk_classes)

    def test_a_probe_is_direct_by_nature(self):
        """TLS evidence cannot be captured through a proxy that terminates TLS,
        so a probe always declares direct transport and is caught by
        require_proxy rather than quietly bypassing it."""
        self.assertIs(TransportProbe("tls").use_proxy, False)

    def test_an_empty_method_does_not_trip_a_method_allowlist(self):
        pol = policy(allow_methods=["POST"])
        self.assertTrue(pol.permits(TransportProbe("tls")))


class TestGateIsEnforced(unittest.TestCase):
    def test_no_policy_means_no_packet(self):
        for fn, args in (
            (tls_posture.client_cert_enforcement, (CLOSED,)),
            (tls_posture.negotiated_parameters, ("127.0.0.1",)),
            (tls_posture.cipher_enumeration, ("127.0.0.1",)),
        ):
            with self.assertRaises(AuthorisationError, msg=fn.__name__):
                fn(*args)

    def test_the_refusal_says_how_to_fix_it(self):
        try:
            tls_posture.negotiated_parameters("127.0.0.1")
        except AuthorisationError as exc:
            self.assertIn("scope", str(exc).lower())
            self.assertIn("transport_probe", str(exc))
        else:
            self.fail("expected AuthorisationError")

    def test_a_policy_denying_transport_probes_refuses(self):
        pol = policy(deny_classes=["transport_probe"])
        with self.assertRaises(AuthorisationError):
            tls_posture.negotiated_parameters("127.0.0.1", scope_policy=pol)

    def test_require_proxy_catches_probes_without_a_direct_authorisation(self):
        pol = policy(require_proxy=True)
        with self.assertRaises(AuthorisationError):
            tls_posture.negotiated_parameters("127.0.0.1", scope_policy=pol)

    def test_a_direct_transport_authorisation_lets_the_probe_run(self):
        pol = policy(require_proxy=True, authorisations=[{
            "classes": ["direct_transport"],
            "authorised_by": "Test Operator",
            "authorised_on": "2026-01-01",
            "reference": "ROE-1 s.3",
        }])
        out = tls_posture.negotiated_parameters("127.0.0.1", port=1,
                                                scope_policy=pol)
        self.assertEqual(out["module"], "tls_posture.negotiated_parameters")

    def test_a_permitted_probe_proceeds_and_stamps_direct(self):
        out = tls_posture.client_cert_enforcement(CLOSED,
                                                  scope_policy=policy())
        self.assertEqual(out["capture_method"], "direct")

    def test_reading_a_certificate_from_disk_needs_no_policy(self):
        """certificate_revocation parses a local file and opens no socket, so
        gating it would be theatre."""
        out = tls_posture.certificate_revocation("/nonexistent.pem")
        self.assertEqual(out["status"], "NOT VERIFIED")
