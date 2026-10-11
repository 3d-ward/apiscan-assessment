import json
import unittest

from tests.support import ROOT, auth_for, load_profile  # noqa: F401
from framework.core.errors import CorpusError
from framework.corpus import payload as PL
from framework.corpus.case import Case, Corpus, find_gaps
from framework.corpus.generators import families as F
from framework.corpus.generators import followup as FU
from framework.corpus.generators import phases as G
from framework.corpus.generators import retest as RT
from framework.methodology import phases as PH


class TestPayloadPaths(unittest.TestCase):
    DOC = {"a": {"b": "v"}, "list": [{"id": 1}, {"id": 2}], "flag": True}

    def test_get(self):
        self.assertEqual(PL.get(self.DOC, "a.b"), "v")
        self.assertEqual(PL.get(self.DOC, "list[1].id"), 2)
        self.assertEqual(PL.get(self.DOC, "missing.x", "D"), "D")

    def test_set_does_not_mutate_the_original(self):
        out = PL.set_(self.DOC, "a.b", "new")
        self.assertEqual(out["a"]["b"], "new")
        self.assertEqual(self.DOC["a"]["b"], "v")

    def test_set_creates_intermediate_objects(self):
        self.assertEqual(PL.set_({}, "x.y.z", 1), {"x": {"y": {"z": 1}}})

    def test_remove(self):
        self.assertNotIn("b", PL.remove(self.DOC, "a.b")["a"])
        self.assertEqual(len(PL.remove(self.DOC, "list[0]")["list"]), 1)

    def test_remove_missing_is_a_noop(self):
        self.assertEqual(PL.remove(self.DOC, "nope.nope"), self.DOC)


class TestCaseModel(unittest.TestCase):
    def test_state_mutating_defaults_to_true(self):
        """Fail safe: an un-annotated case is assumed dangerous, so forgetting
        to annotate denies rather than sends."""
        self.assertTrue(Case("T", "e", "reject", "d").state_mutating)

    def test_invalid_enums_are_rejected(self):
        for kwargs in ({"expectation": "maybe"},
                       {"expectation": "reject", "volume_class": "huge"},
                       {"expectation": "reject", "payload_class": "weird"},
                       {"expectation": "reject", "severity_if_accepted": "Bad"}):
            with self.assertRaises(ValueError):
                Case("T", "e", **dict({"description": "d"}, **kwargs))

    def test_duplicate_ids_are_rejected(self):
        with self.assertRaises(CorpusError):
            Corpus([Case("X", "e", "reject", "d"),
                    Case("X", "e", "reject", "d")])

    def test_round_trip_through_json(self):
        corpus = Corpus([Case("A", "e", "reject", "d", phase="P1")])
        restored = Corpus.from_json(corpus.to_json())
        self.assertEqual(restored.cases[0].id, "A")
        self.assertEqual(restored.cases[0].phase, "P1")

    def test_gap_detection(self):
        corpus = Corpus([Case("A", "create", "reject", "d", phase="P1")])
        gaps = find_gaps(corpus, ["P1", "P2"], ["create", "update"])
        self.assertIn(("P1", "update"), gaps)
        self.assertIn(("P2", "create"), gaps)


class TestPhaseMethodology(unittest.TestCase):
    def test_ordering_is_a_safety_property(self):
        """Phases run least-to-most state-mutating so a run can stop at a
        boundary. Reshuffling them is not a presentation choice."""
        self.assertTrue(PH.is_monotonic_in_mutation())
        self.assertEqual(PH.ORDERED_IDS,
                         ["P1", "P2", "P3", "P4", "P5", "P6", "P7"])

    def test_authz_and_authn_precede_mutating_phases(self):
        weights = {p["id"]: p["ordering_weight"] for p in PH.PHASES}
        for early in ("P1", "P2"):
            for late in ("P3", "P4", "P5"):
                self.assertLess(weights[early], weights[late])

    def test_every_phase_declares_owasp_and_default_mutation(self):
        for phase in PH.PHASES:
            self.assertTrue(phase["owasp"])
            self.assertIn("default_mutating", phase)

    def test_truncation(self):
        self.assertEqual([p["id"] for p in PH.ordered("P3")],
                         ["P1", "P2", "P3"])


class TestGenerators(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load_profile()
        cls.auth = auth_for(cls.profile)
        cls.families = F.generate(cls.profile, auth_provider=cls.auth)
        cls.phases = G.generate(cls.profile, cls.auth)

    def test_all_ten_families_produce_cases(self):
        produced = {c.family for c in self.families}
        self.assertEqual(produced, set("ABCDEFGHIJ"))

    def test_all_seven_phases_produce_cases(self):
        produced = {c.phase for c in self.phases}
        self.assertEqual(produced, set(PH.ORDERED_IDS))

    def test_every_case_is_valid_and_uniquely_identified(self):
        corpus = Corpus(self.families + self.phases)
        self.assertEqual(len(corpus), len(self.families) + len(self.phases))

    def test_bodies_are_valid_json_except_deliberate_malformed_cases(self):
        for case in self.families + self.phases:
            if case.body is None or case.payload_class == "malformed":
                continue
            json.loads(case.body)

    def test_malformed_cases_really_are_malformed(self):
        malformed = [c for c in self.families
                     if c.payload_class == "malformed"]
        self.assertTrue(malformed)
        unparseable = 0
        for case in malformed:
            try:
                json.loads(case.body)
            except ValueError:
                unparseable += 1
        self.assertGreater(unparseable, 0)

    def test_no_two_cases_share_a_correlation_identifier(self):
        """Sharing one body across cases would replay the same identifier, and
        a target with idempotency protection would refuse everything after the
        first -- turning the whole family into a business-layer rejection."""
        seen = []
        for case in self.families + self.phases:
            if not case.body:
                continue
            try:
                value = json.loads(case.body).get("correlationId")
            except (ValueError, AttributeError):
                continue
            if isinstance(value, str) and len(value) == 64 \
                    and all(ch in "0123456789abcdef" for ch in value):
                seen.append(value)
        self.assertEqual(len(seen), len(set(seen)),
                         "duplicate correlation identifiers generated")

    def test_cross_namespace_substitution_only_crosses_namespaces(self):
        for case in [c for c in self.families if c.family == "A"]:
            self.assertEqual(case.payload_class, "identifier")
            self.assertEqual(case.severity_if_accepted, "High")

    def test_header_case_variation_is_a_baseline_not_a_defect(self):
        """HTTP header names are case-insensitive, so acceptance is CORRECT.
        Declaring it 'reject' would record correct behaviour as a win."""
        variants = [c for c in self.families
                    if c.family == "J" and "case-varied" in c.description]
        self.assertTrue(variants)
        for case in variants:
            self.assertEqual(case.expectation, "accept")

    def test_oversize_and_depth_cases_are_classed_volumetric(self):
        risky = [c for c in self.families
                 if c.payload_class == "oversize"
                 or "nested" in c.description]
        self.assertTrue(risky)
        for case in risky:
            self.assertIn("volumetric", case.risk_classes)

    def test_phase_cases_inherit_the_phase_mutation_default(self):
        for case in self.phases:
            if case.phase in ("P3", "P4", "P5"):
                self.assertTrue(case.state_mutating, case.id)

    def test_up_to_truncates_at_a_phase_boundary(self):
        self.assertEqual(
            {c.phase for c in G.generate(self.profile, self.auth, up_to="P3")},
            {"P1", "P2", "P3"})


class TestRetestAndFollowup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load_profile()

    def test_baseline_cases_expect_acceptance(self):
        for case in RT.baseline_cases(self.profile):
            self.assertEqual(case.expectation, "accept")

    def test_failing_baseline_makes_a_run_inconclusive(self):
        """Without calibration a negative result cannot be told apart from a
        broken harness."""
        records = [{"case_id": "BASE-x", "verdict": "OVER-BLOCKED"}]
        ok, summary = RT.assess_baseline(records)
        self.assertFalse(ok)
        self.assertIn("INCONCLUSIVE", summary)

    def test_absent_baseline_is_also_not_trustworthy(self):
        ok, summary = RT.assess_baseline([{"case_id": "C01",
                                           "verdict": "CONTROL-PRESENT"}])
        self.assertFalse(ok)
        self.assertIn("no baseline", summary)

    def test_passing_baseline(self):
        ok, _ = RT.assess_baseline([{"case_id": "BASE-x",
                                     "verdict": "CONTROL-PRESENT"}])
        self.assertTrue(ok)

    def test_remediation_item_kinds_are_validated(self):
        with self.assertRaises(ValueError):
            RT.RetestItem("V1", "t", remediation_items=[{"kind": "invented"}])

    def test_followup_probes_are_available(self):
        self.assertEqual(
            set(FU.available()),
            {"case_sensitivity", "scope_of_fix", "cross_endpoint", "per_node",
             "credential_lifecycle", "response_headers", "method_and_media"})

    def test_case_sensitivity_probe_includes_a_control(self):
        cases = FU.case_sensitivity(self.profile, "a" * 64)
        self.assertEqual(len(cases), 3)
        self.assertTrue(any("control" in c.description for c in cases))

    def test_credential_lifecycle_does_not_overclaim(self):
        case = FU.credential_lifecycle(self.profile)[0]
        self.assertEqual(case.expectation, "observe")
        self.assertIn("NOT observable", case.notes)

    def test_response_header_assessment(self):
        result = FU.assess_response_headers(
            "HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\n"
            "X-Content-Type-Options: nosniff")
        self.assertTrue(any(m["header"] == "Strict-Transport-Security"
                            for m in result["missing"]))
        self.assertTrue(any(a["header"] == "Server"
                            for a in result["advertised"]))


if __name__ == "__main__":
    unittest.main()
