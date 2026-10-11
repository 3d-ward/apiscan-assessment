import os
import shutil
import tempfile
import unittest

from tests.support import ROOT, load_profile, auth_for  # noqa: F401
from framework.core import auth as A
from framework.core.errors import PathGuardError
from framework.core.pathguard import (FRAMEWORK_ROOT, assert_outside_framework,
                                      ensure_engagement_dir, is_within)
from framework.core.transport import Transport, split_last_response


class TestPathGuard(unittest.TestCase):
    """Engagement data inside the framework tree is the most likely route for
    client material into a shared repository, so it is refused structurally."""

    def test_framework_paths_are_refused(self):
        for path in ("evidence", "reports", "configs/examples/x"):
            with self.assertRaises(PathGuardError):
                assert_outside_framework(os.path.join(FRAMEWORK_ROOT, path))

    def test_outside_paths_are_allowed(self):
        self.assertTrue(assert_outside_framework(
            tempfile.gettempdir() + "/apiscan-guard-ok"))

    def test_symlink_into_the_framework_is_caught(self):
        tmp = tempfile.mkdtemp(prefix="apiscan-guard-")
        try:
            link = os.path.join(tmp, "sneaky")
            os.symlink(FRAMEWORK_ROOT, link)
            with self.assertRaises(PathGuardError):
                assert_outside_framework(os.path.join(link, "evidence"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_sibling_prefix_is_not_containment(self):
        self.assertFalse(is_within(FRAMEWORK_ROOT + "-audit", FRAMEWORK_ROOT))

    def test_ensure_engagement_dir_creates(self):
        tmp = tempfile.mkdtemp(prefix="apiscan-guard-")
        try:
            path = ensure_engagement_dir(os.path.join(tmp, "a", "b"))
            self.assertTrue(os.path.isdir(path))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestResponseSplitting(unittest.TestCase):
    """Through a proxy, curl emits the CONNECT block first. Splitting on the
    first blank line hands back the wrong headers -- silently."""

    def test_proxied_returns_the_real_response(self):
        blob = ("HTTP/1.1 200 Connection established\r\n\r\n"
                "HTTP/1.1 409 Conflict\r\nX-Real: yes\r\n\r\n{\"a\":1}")
        headers, body = split_last_response(blob)
        self.assertIn("409", headers)
        self.assertIn("X-Real", headers)
        self.assertEqual(body, '{"a":1}')

    def test_direct(self):
        headers, body = split_last_response(
            "HTTP/1.1 200 OK\r\nA: 1\r\n\r\nbody")
        self.assertIn("200", headers)
        self.assertEqual(body, "body")

    def test_interim_1xx_is_skipped(self):
        headers, _ = split_last_response(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\n\r\nok")
        self.assertIn("201", headers)

    def test_degenerate_inputs(self):
        self.assertEqual(split_last_response(""), ("", ""))
        self.assertEqual(split_last_response("garbage"), ("", "garbage"))
        self.assertEqual(split_last_response("HTTP/1.1 204 No Content\r\nC: 3"),
                         ("HTTP/1.1 204 No Content\r\nC: 3", ""))


class TestTransportArgs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-tx-")
        self.profile = load_profile(base_url="http://127.0.0.1:1/v1",
                                    proxy="http://127.0.0.1:8080")
        self.transport = Transport(self.profile, auth_for(self.profile),
                                   body_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_proxy_args_present_when_proxied(self):
        args = self.transport.build_args("http://api.example.com/y")
        self.assertIn("-x", args)
        self.assertIn("--proxy-insecure", args)

    def test_proxy_args_absent_when_direct(self):
        args = self.transport.build_args("http://api.example.com/y", use_proxy=False)
        self.assertNotIn("-x", args)

    def test_expect_header_is_suppressed(self):
        args = self.transport.build_args("http://api.example.com/y")
        self.assertIn("Expect:", args)

    def test_method_and_url_positions(self):
        args = self.transport.build_args("http://api.example.com/y", method="DELETE")
        self.assertEqual(args[-1], "http://api.example.com/y")
        self.assertEqual(args[args.index("-X") + 1], "DELETE")

    def test_header_overrides_flow_through(self):
        args = self.transport.build_args(
            "http://api.example.com/y", header_overrides={"x-client-token": None})
        joined = " ".join(args)
        self.assertNotIn("x-client-token", joined)

    def test_empty_content_type_is_a_suppression(self):
        args = self.transport.build_args("http://api.example.com/y", content_type="")
        self.assertIn("Content-Type;", args)


class TestAuthProviders(unittest.TestCase):
    def test_bearer_and_basic(self):
        bearer = A.BearerAuth(
            {"a": {"purpose": "positive", "headers": {"token": "T"}}}, "a")
        self.assertEqual(bearer.headers_for(), {"Authorization": "Bearer T"})
        basic = A.BasicAuth(
            {"a": {"purpose": "positive",
                   "headers": {"username": "u", "password": "p"}}}, "a")
        self.assertEqual(basic.headers_for(), {"Authorization": "Basic dTpw"})

    def test_none_provider(self):
        self.assertEqual(A.NoAuth({"a": {"purpose": "positive"}},
                                  "a").headers_for(), {})

    def test_purpose_lookup(self):
        provider = A.HeaderTokenAuth(
            {"a": {"purpose": "positive"}, "b": {"purpose": "wrong_role"},
             "c": {"purpose": "invalid_credential"}}, "a")
        self.assertEqual(provider.identities_with_purpose("wrong_role"), ["b"])
        self.assertEqual(provider.identities_with_purpose("invalid_credential"),
                         ["c"])

    def test_unknown_identity_raises(self):
        from framework.core.errors import ProfileError
        provider = A.HeaderTokenAuth({"a": {"purpose": "positive"}}, "a")
        with self.assertRaises(ProfileError):
            provider.headers_for("nope")


if __name__ == "__main__":
    unittest.main()
