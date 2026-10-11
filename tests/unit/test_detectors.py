import unittest

from tests.support import ROOT  # noqa: F401
from framework.oracle import detectors as D

RULES = D.load_rules()

POSITIVE = {
    "DISC-STACK-JAVA": "at com.example.Svc.run(Svc.java:42)",
    "DISC-STACK-PYTHON": 'Traceback (most recent call last):',
    "DISC-STACK-DOTNET": "System.NullReferenceException occurred",
    "DISC-STACK-NODE": "at handler (/srv/node_modules/a.js:1)",
    "DISC-STACK-PHP": "PHP Fatal error: boom",
    "DISC-STACK-GO": "goroutine 1 [running]:",
    "DISC-STACK-RUBY": "app/models/user.rb:12:in `find'",
    "DISC-SQL": 'ERROR: syntax error at or near "SELECT"',
    "DISC-PATH-WIN": "C:\\inetpub\\wwwroot\\app",
    "DISC-CLOUD-META": '{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE"}',
    "DISC-SECRET-SHAPE": '{"password":"hunter2abc"}',
    "DISC-INTERNAL-HOST": "upstream 10.0.3.14 failed",
    "DISC-VERSION": "nginx/1.24.0",
}

CLEAN = [
    '{"resultCode":"0000","resultMessage":"Success"}',
    '{"resultCode":"0400","resultMessage":"Field is required"}',
    '{"data":[{"id":"SYNTH-AB1234567","state":"COMPLETE"}]}',
    "",
    "OK",
]


class TestDisclosureDetectors(unittest.TestCase):
    def test_every_rule_has_a_positive_fixture(self):
        covered = set(POSITIVE) | {"DISC-PATH-UNIX", "DISC-DEBUG"}
        missing = [r.id for r in RULES if r.id not in covered]
        self.assertEqual(missing, [], "rules without a test fixture: %s"
                         % missing)

    def test_positive_fixtures_fire_the_right_rule(self):
        for rule_id, sample in POSITIVE.items():
            hits = [h.rule_id for h in D.scan_disclosure(sample, RULES)]
            self.assertIn(rule_id, hits, "%s did not fire on %r"
                          % (rule_id, sample))

    def test_clean_responses_produce_no_hits(self):
        for sample in CLEAN:
            self.assertEqual(D.scan_disclosure(sample, RULES), [], sample)

    def test_rule_ids_are_unique(self):
        ids = [r.id for r in RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_declares_severity_and_cwe(self):
        for rule in RULES:
            self.assertTrue(rule.severity, rule.id)
            self.assertTrue(rule.cwe or rule.severity == "Informational",
                            rule.id)


class TestReflection(unittest.TestCase):
    VECTOR = "<script>alert(document.domain)</script>"

    def test_verbatim(self):
        hit = D.scan_reflection(self.VECTOR, "echo " + self.VECTOR,
                                payload_class="injection")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.severity, "High")

    def test_encoded_variants_still_count(self):
        for body in ("echo &lt;script&gt;alert(document.domain)&lt;/script&gt;",
                     "echo %3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E"):
            self.assertIsNotNone(
                D.scan_reflection(self.VECTOR, body,
                                  payload_class="injection"), body)

    def test_absent(self):
        self.assertIsNone(D.scan_reflection(self.VECTOR, "nothing here"))

    def test_short_values_are_ignored(self):
        self.assertIsNone(D.scan_reflection("abc", "abc is here"))

    def test_non_injection_is_lower_severity(self):
        hit = D.scan_reflection("SYNTH-AB1234567", "id SYNTH-AB1234567",
                                payload_class="benign")
        self.assertEqual(hit.severity, "Low")


if __name__ == "__main__":
    unittest.main()
