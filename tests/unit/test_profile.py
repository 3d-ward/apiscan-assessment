import unittest

from tests.support import ROOT, TEST_ENV, load_profile, raw_profile  # noqa: F401
from framework.core import profile as P
from framework.core.errors import ProfileError, SecretInProfileError


class TestSecretRefusal(unittest.TestCase):
    """A profile is a config artifact that gets committed and shared.
    A literal credential in one is a confidentiality incident, so the loader
    refuses rather than warns."""

    def scan(self, doc):
        return P.scan_for_literal_secrets(doc)

    def test_literal_in_credential_location_is_refused(self):
        self.assertTrue(self.scan(
            {"auth": {"identities": {"p": {"headers": {
                "x-client-token": "Zq4Tn8Bv6Wd3Yh1Kq7Zp2Lm9Xr5"}}}}}))

    def test_literal_under_an_unusual_header_name_is_refused(self):
        self.assertTrue(self.scan(
            {"auth": {"identities": {"p": {"headers": {
                "x-weird": "Kq7Zp2Lm9Xr4Tn8Bv6Wd3Yh1"}}}}}))

    def test_credential_key_name_anywhere_is_refused(self):
        self.assertTrue(self.scan({"db": {"password": "hunter2"}}))
        self.assertTrue(self.scan({"h": {"Authorization": "Bearer x"}}))

    def test_hard_secret_shapes(self):
        for value in ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_value_here",
                      "AKIAIOSFODNN7EXAMPLE",
                      "-----BEGIN RSA PRIVATE KEY-----"):
            self.assertTrue(self.scan({"x": {"v": value}}), value)

    def test_env_reference_passes(self):
        self.assertEqual(self.scan(
            {"auth": {"identities": {"p": {"headers": {
                "x-client-token": "${ENV:T}"}}}}}), [])

    def test_no_false_positive_on_legitimate_config(self):
        """These all tripped an earlier, looser heuristic."""
        for doc in (
            {"auth": {"provider": "header_token",
                      "default_identity": "primary"}},
            {"auth": {"identities": {"p": {
                "purpose": "positive", "role": "api-user",
                "description": "Correct role, valid credential."}}}},
            {"identifier_spaces": {"c": {"example": "0" * 64}}},
            {"body": {"correlationId": "a3f9c2e4b7d1086f5a2c9e3b4d7f1028"
                                       "a3f9c2e4b7d1086f5a2c9e3b4d7f1028"}},
            {"transport": {"base_url": "https://api.example.com/v1"}},
            {"transport": {"proxy": "http://127.0.0.1:8080"}},
            {"transport": {"cert_path": "/engagements/x/client.crt"}},
            {"identity": {"name": "example-callback-api"}},
            {"x": {"v": "00000000-0000-4000-8000-000000000000"}},
            {"notes": ["This profile is referenced by the test suite."]},
            {"response_model": {"envelope": {"auth_failure_values": ["0401"]}}},
        ):
            self.assertEqual(self.scan(doc), [], doc)

    def test_loader_raises_on_literal_secret(self):
        data = raw_profile()
        data["auth"]["identities"]["primary"]["headers"]["x-client-token"] = \
            "Kq7Zp2Lm9Xr4Tn8Bv6Wd3Yh1"
        with self.assertRaises(SecretInProfileError):
            P.load_data(data, env=TEST_ENV)


class TestProfileLoading(unittest.TestCase):
    def test_example_profile_loads(self):
        profile = load_profile()
        self.assertEqual(len(profile.endpoint_ids), 4)
        self.assertEqual(len(profile.resolved_env), 6)
        self.assertTrue(profile.envelope)

    def test_missing_env_is_an_error(self):
        with self.assertRaises(ProfileError):
            load_profile(env={})

    def test_unknown_endpoint_raises(self):
        with self.assertRaises(ProfileError):
            load_profile().endpoint("nope")

    def test_cross_reference_checks(self):
        data = raw_profile()
        data["endpoints"][0]["identifier_space"] = "does-not-exist"
        with self.assertRaises(ProfileError):
            P.load_data(data, env=TEST_ENV)

        data = raw_profile()
        data["auth"]["default_identity"] = "missing"
        with self.assertRaises(ProfileError):
            P.load_data(data, env=TEST_ENV)

        data = raw_profile()
        data["endpoints"][1]["id"] = data["endpoints"][0]["id"]
        with self.assertRaises(ProfileError):
            P.load_data(data, env=TEST_ENV)

    def test_identifier_generators(self):
        profile = load_profile()
        for endpoint in profile.endpoint_ids:
            first = profile.identifier_for(endpoint)
            second = profile.identifier_for(endpoint)
            self.assertTrue(first)
            self.assertNotEqual(first, second,
                                "identifiers must be fresh per call")

    def test_url_building(self):
        profile = load_profile(base_url="http://127.0.0.1:1/v1")
        self.assertEqual(profile.url_for("audit_entry"),
                         "http://127.0.0.1:1/v1/notify/audit-entry")


if __name__ == "__main__":
    unittest.main()
