"""Socket-level proof that the test suite performs no outbound connection.

The suite's isolation previously rested on an argument -- the mock binds to
loopback, and no external host appears in the tree -- rather than on evidence.
This module instruments `socket.socket.connect` itself, so any attempt to reach
a non-loopback address during a representative run is recorded and fails the
test. It closes the one caveat the independent validator's behavioural check
had to state.

Note what this does and does not prove: it covers connections made from inside
this Python process. The framework's transport shells out to `curl`, so a
subprocess connection would not be seen here -- which is exactly why the
corresponding test asserts on the *arguments* curl would be given instead.
"""
import ipaddress
import socket
import unittest

from tests.support import test_scope, ROOT, auth_for, load_profile  # noqa: F401


def _is_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "localhost.localdomain", "")


class EgressRecorder(object):
    """Context manager recording every outbound connect attempt."""

    def __init__(self):
        self.attempts = []
        self._real_connect = None
        self._real_connect_ex = None
        self._real_getaddrinfo = None
        self.resolutions = []

    def __enter__(self):
        self._real_connect = socket.socket.connect
        self._real_connect_ex = socket.socket.connect_ex
        self._real_getaddrinfo = socket.getaddrinfo
        recorder = self

        def connect(sock, address, *args, **kwargs):
            recorder.attempts.append(address)
            return recorder._real_connect(sock, address, *args, **kwargs)

        def connect_ex(sock, address, *args, **kwargs):
            recorder.attempts.append(address)
            return recorder._real_connect_ex(sock, address, *args, **kwargs)

        def getaddrinfo(host, *args, **kwargs):
            recorder.resolutions.append(host)
            return recorder._real_getaddrinfo(host, *args, **kwargs)

        socket.socket.connect = connect
        socket.socket.connect_ex = connect_ex
        socket.getaddrinfo = getaddrinfo
        return self

    def __exit__(self, *exc):
        socket.socket.connect = self._real_connect
        socket.socket.connect_ex = self._real_connect_ex
        socket.getaddrinfo = self._real_getaddrinfo
        return False

    def external(self):
        out = []
        for address in self.attempts:
            host = address[0] if isinstance(address, tuple) else str(address)
            if not _is_loopback(str(host)):
                out.append(address)
        return out

    def external_resolutions(self):
        return [h for h in self.resolutions
                if h and not _is_loopback(str(h))]


class TestNoEgress(unittest.TestCase):
    def test_corpus_generation_opens_no_socket(self):
        with EgressRecorder() as rec:
            from framework.corpus.generators import families as F
            from framework.corpus.generators import phases as G
            profile = load_profile()
            auth = auth_for(profile)
            F.generate(profile, auth_provider=auth)
            G.generate(profile, auth)
        self.assertEqual(rec.attempts, [],
                         "corpus generation opened a socket")

    def test_a_full_run_against_the_mock_touches_only_loopback(self):
        import os
        import shutil
        import tempfile

        from tests.fixtures.mock_service import MockService
        from framework import runner as RUN
        from framework.corpus.case import Corpus
        from framework.corpus.generators import families as F
        from framework.evidence.store import EvidenceStore
        from framework.governance.scope import ScopePolicy

        tmp = tempfile.mkdtemp(prefix="apiscan-egress-")
        try:
            with EgressRecorder() as rec:
                with MockService() as svc:
                    profile = load_profile(base_url=svc.base_url, proxy=None)
                    auth = auth_for(profile)
                    corpus = Corpus(F.generate(profile, auth_provider=auth,
                                               families=["C", "H"]))
                    store = EvidenceStore(os.path.join(tmp, "evidence"))
                    RUN.Runner(profile, auth, store,
                               scope_policy=ScopePolicy({
                                   "schema": "scope-policy/1",
                                   "deny_classes": ["volumetric"]}),
                               via_proxy=False, delay_s=0).run(list(corpus))
                    store.finalise()
            self.assertEqual(rec.external(), [],
                             "a run connected to a non-loopback address")
            self.assertEqual(rec.external_resolutions(), [],
                             "a run resolved an external hostname")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_curl_is_only_ever_pointed_at_the_configured_target(self):
        """The transport shells out, so assert on the arguments instead."""
        import tempfile

        from framework.core.transport import Transport
        tmp = tempfile.mkdtemp(prefix="apiscan-args-")
        profile = load_profile(base_url="http://127.0.0.1:9/v1", proxy=None)
        transport = Transport(profile, auth_for(profile), body_dir=tmp,
                              via_proxy=False, scope_policy=test_scope())
        args = transport.build_args(profile.url_for("resource_create"))
        urls = [a for a in args if a.startswith(("http://", "https://"))]
        self.assertEqual(urls, ["http://127.0.0.1:9/v1/notify/created"])
        self.assertNotIn("-x", args, "no proxy should be configured here")

    def test_the_mock_binds_only_to_loopback(self):
        from tests.fixtures.mock_service import MockService
        with MockService() as svc:
            host, port = svc.server.server_address[:2]
            self.assertTrue(_is_loopback(host),
                            "the mock bound to %r, not loopback" % host)
            self.assertTrue(svc.base_url.startswith("http://127.0.0.1:"))


if __name__ == "__main__":
    unittest.main()
