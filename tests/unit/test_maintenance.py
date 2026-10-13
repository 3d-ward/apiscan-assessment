"""Snapshot/rollback and improvement-intake controls.

These are the mechanisms that make a change reversible and make an unvetted
change impossible, so they need the same evidence as anything else.
"""
import json
import os
import shutil
import tempfile
import unittest

from tests.support import ROOT  # noqa: F401
from automation.maintenance import intake, snapshot


class TestSnapshotRollback(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-snap-")
        self.fw = os.path.join(self.tmp, "fw")
        self.store = os.path.join(self.tmp, "store")
        os.makedirs(os.path.join(self.fw, "pkg"))
        self._write("pkg/mod.py", "VALUE = 1\n")
        self._write("README.md", "original\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel, text):
        path = os.path.join(self.fw, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)

    def _read(self, rel):
        with open(os.path.join(self.fw, rel)) as fh:
            return fh.read()

    def test_snapshot_captures_source_and_verifies(self):
        path = snapshot.create("t", self.store, self.fw)
        with open(os.path.join(path, "manifest.json")) as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest["file_count"], 2)
        self.assertEqual(snapshot.verify(manifest["id"], self.store), [])

    def test_snapshot_excludes_secrets_and_artifacts(self):
        self._write(".env", "TOKEN=secret\n")
        self._write("client.p12", "binary\n")
        self._write("evidence/run/C01.resp.txt", "captured\n")
        os.makedirs(os.path.join(self.fw, "__pycache__"), exist_ok=True)
        self._write("__pycache__/x.pyc", "bytecode\n")
        path = snapshot.create("t", self.store, self.fw)
        with open(os.path.join(path, "manifest.json")) as fh:
            paths = {e["path"] for e in json.load(fh)["files"]}
        self.assertNotIn(".env", paths)
        self.assertNotIn("client.p12", paths)
        self.assertNotIn(os.path.join("__pycache__", "x.pyc"), paths)
        self.assertIn("README.md", paths)

    def test_rollback_restores_content(self):
        snap_id = os.path.basename(snapshot.create("before", self.store, self.fw))
        self._write("pkg/mod.py", "VALUE = 999\n")
        self._write("README.md", "changed\n")
        restored = snapshot.rollback(snap_id, self.store, self.fw,
                                     safety_snapshot=False)
        self.assertEqual(restored, 2)
        self.assertEqual(self._read("pkg/mod.py"), "VALUE = 1\n")
        self.assertEqual(self._read("README.md"), "original\n")

    def test_rollback_is_itself_reversible(self):
        """Without a safety snapshot the first rollback destroys the only copy
        of whatever it replaced."""
        first = os.path.basename(snapshot.create("v1", self.store, self.fw))
        self._write("pkg/mod.py", "VALUE = 2\n")
        snapshot.rollback(first, self.store, self.fw, safety_snapshot=True)
        self.assertEqual(self._read("pkg/mod.py"), "VALUE = 1\n")
        safety = [s for s in snapshot.listing(self.store)
                  if s["label"].startswith("pre-rollback")]
        self.assertEqual(len(safety), 1)
        snapshot.rollback(safety[0]["id"], self.store, self.fw,
                          safety_snapshot=False)
        self.assertEqual(self._read("pkg/mod.py"), "VALUE = 2\n")

    def test_unknown_snapshot_raises(self):
        with self.assertRaises(ValueError):
            snapshot.rollback("no-such-snapshot", self.store, self.fw)

    def test_diff_reports_changes(self):
        snap_id = os.path.basename(snapshot.create("v1", self.store, self.fw))
        self._write("pkg/mod.py", "VALUE = 3\n")
        self._write("pkg/new.py", "x = 1\n")
        os.remove(os.path.join(self.fw, "README.md"))
        diff = snapshot.diff_against_current(snap_id, self.store, self.fw)
        self.assertIn(os.path.join("pkg", "mod.py"), diff["changed"])
        self.assertIn(os.path.join("pkg", "new.py"), diff["added"])
        self.assertIn("README.md", diff["removed"])


class TestImprovementIntake(unittest.TestCase):
    """The gates that stop an unvetted change reaching the framework."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="apiscan-intake-")
        self.quarantine = os.path.join(self.tmp, "quarantine")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def candidate(self, **kw):
        defaults = dict(
            name="probe", files={"framework/oracle/rules/extra.json": "{}\n"},
            kind="ENGINEERING IMPROVEMENT", rationale="adds a detector rule")
        defaults.update(kw)
        return intake.Candidate(**defaults)

    # -- G1 isolation ---------------------------------------------------
    def test_escaping_the_framework_is_refused(self):
        for path in ("../outside.py", "/etc/passwd",
                     "../apiscan-assessment-audit/validation/validator.py"):
            result = intake.gate_isolation(
                self.candidate(files={path: "x"}), ROOT)
            self.assertEqual(result.status, intake.FAIL, path)

    def test_touching_the_validator_is_refused(self):
        """The thing being checked must not be able to adjust the check."""
        result = intake.gate_isolation(
            self.candidate(files={"tools/validator.py": "x"}), ROOT)
        self.assertEqual(result.status, intake.FAIL)

    def test_writing_into_an_artifact_directory_is_refused(self):
        result = intake.gate_isolation(
            self.candidate(files={"evidence/x.txt": "x"}), ROOT)
        self.assertEqual(result.status, intake.FAIL)

    def test_the_artifact_directory_screen_is_separator_agnostic(self):
        """Regression, first Windows CI run of 1.1.0.

        The screen normalised with ``os.path.normpath``, which returns
        BACKSLASH-separated paths on Windows, so splitting on "/" saw
        ``evidence\\x.txt`` as a single component and the gate failed OPEN
        there. Asserting the normalised FORM rather than one platform's
        gate verdict is what makes this test fail on the host that had the
        bug.
        """
        for spelling in ("evidence/x.txt", "evidence\\x.txt",
                         "./evidence/x.txt", "reports/../evidence/x.txt"):
            self.assertEqual(intake._normalise(spelling).split("/")[0],
                             "evidence", spelling)
            self.assertEqual(
                intake.gate_isolation(
                    self.candidate(files={spelling: "x"}), ROOT).status,
                intake.FAIL, spelling)

    def test_a_normal_path_passes(self):
        self.assertEqual(intake.gate_isolation(self.candidate(), ROOT).status,
                         intake.PASS)

    # -- G2 sanitisation ------------------------------------------------
    def test_a_credential_shaped_literal_is_refused(self):
        result = intake.gate_sanitisation(
            self.candidate(files={"framework/x.py":
                                  'KEY = "AKIAIOSFODNN7EXAMPLE"\n'}), ROOT)
        self.assertEqual(result.status, intake.FAIL)

    def test_a_forbidden_term_is_refused(self):
        result = intake.gate_sanitisation(
            self.candidate(files={"framework/x.py": "# acme-internal host\n"}),
            ROOT, extra_terms=["acme-internal"])
        self.assertEqual(result.status, intake.FAIL)

    def test_clean_content_passes(self):
        self.assertEqual(
            intake.gate_sanitisation(
                self.candidate(files={"framework/x.py": "X = 1\n"}),
                ROOT).status, intake.PASS)

    # -- G3 static ------------------------------------------------------
    def test_a_syntax_error_is_refused(self):
        result = intake.gate_static(
            self.candidate(files={"framework/x.py": "def broken(:\n"}), ROOT)
        self.assertEqual(result.status, intake.FAIL)

    def test_a_module_level_target_constant_is_refused(self):
        result = intake.gate_static(
            self.candidate(files={"framework/x.py":
                                  'BASE = "https://api.acme.example"\n'}), ROOT)
        self.assertEqual(result.status, intake.FAIL)

    # -- G6 independent -------------------------------------------------
    def test_a_missing_validator_is_not_verified_never_pass(self):
        """An unavailable check is not a passed check."""
        result = intake.gate_independent(self.candidate(), ROOT,
                                         "/nonexistent/validator.py")
        self.assertEqual(result.status, intake.NOT_VERIFIED)
        self.assertNotEqual(result.status, intake.PASS)

    # -- G8 provenance --------------------------------------------------
    def test_provenance_must_be_declared(self):
        self.assertEqual(
            intake.gate_provenance(self.candidate(kind="something"),
                                   ROOT).status, intake.FAIL)
        self.assertEqual(
            intake.gate_provenance(self.candidate(rationale="  "),
                                   ROOT).status, intake.FAIL)
        self.assertEqual(intake.gate_provenance(self.candidate(), ROOT).status,
                         intake.PASS)

    # -- G9 rollback ----------------------------------------------------
    def test_no_snapshot_means_no_integration(self):
        self.assertEqual(
            intake.gate_rollback(self.candidate(), ROOT, None).status,
            intake.FAIL)

    # -- quarantine and atomicity ---------------------------------------
    def test_quarantine_keeps_the_candidate_and_the_reason(self):
        results = [intake.GateResult("G1_isolation", intake.FAIL, "nope")]
        dest = intake.quarantine(self.candidate(), results, self.quarantine,
                                 "test")
        with open(os.path.join(dest, "quarantine.json")) as fh:
            record = json.load(fh)
        self.assertEqual(record["reason"], "test")
        self.assertEqual(record["gates"][0]["status"], intake.FAIL)
        self.assertTrue(os.path.exists(os.path.join(
            dest, "files", "framework", "oracle", "rules", "extra.json")))

    def test_a_failing_candidate_is_quarantined_and_applies_nothing(self):
        before = sorted(os.listdir(ROOT))
        bad = self.candidate(files={"../escape.py": "x"})
        integrated, results, detail = intake.process(
            bad, framework=ROOT, quarantine_dir=self.quarantine)
        self.assertFalse(integrated)
        self.assertEqual(sorted(os.listdir(ROOT)), before,
                         "a rejected candidate changed the framework tree")
        self.assertTrue(os.path.isdir(detail))

    def test_dry_run_leaves_the_tree_untouched(self):
        """Orchestration only.

        The functional, security and independent gates are stubbed: each is
        tested on its own above, and running them for real here would re-invoke
        the entire test suite (and the external validator) from inside a test,
        which is both recursive and slow.
        """
        marker = os.path.join(ROOT, "framework", "oracle", "rules",
                              "_intake_probe.json")
        self.assertFalse(os.path.exists(marker))
        candidate = self.candidate(
            files={"framework/oracle/rules/_intake_probe.json":
                   '{"schema": "detector-rules/1", "rules": []}\n'})

        real = (intake.gate_functional, intake.gate_security,
                intake.gate_independent)
        staged_during_run = {}

        def ok(gate_name):
            def stub(cand, framework, *args, **kw):
                # Prove the candidate really was applied while the gates ran.
                staged_during_run[gate_name] = os.path.exists(marker)
                return intake.GateResult(gate_name, intake.PASS, "stubbed")
            return stub

        intake.gate_functional = ok("G4_functional")
        intake.gate_security = ok("G5_security")
        intake.gate_independent = ok("G6_independent")
        try:
            integrated, results, detail = intake.process(
                candidate, framework=ROOT, quarantine_dir=self.quarantine,
                snapshot_store=os.path.join(self.tmp, "snaps"), dry_run=True)
        finally:
            (intake.gate_functional, intake.gate_security,
             intake.gate_independent) = real

        self.assertFalse(integrated, "a dry run must not integrate")
        self.assertTrue(staged_during_run.get("G4_functional"),
                        "gates must run against the staged tree")
        self.assertFalse(os.path.exists(marker),
                         "a dry run left a file behind")
        self.assertTrue(os.path.isdir(detail))

    def test_a_failing_gate_reverts_the_staged_files(self):
        """Partial integration must be impossible: a half-applied change
        leaves the framework in a state no snapshot describes."""
        marker = os.path.join(ROOT, "framework", "oracle", "rules",
                              "_intake_fail_probe.json")
        self.assertFalse(os.path.exists(marker))
        candidate = self.candidate(
            files={"framework/oracle/rules/_intake_fail_probe.json": "{}\n"})

        real = (intake.gate_functional, intake.gate_security,
                intake.gate_independent)
        intake.gate_functional = lambda c, f, *a, **k: intake.GateResult(
            "G4_functional", intake.FAIL, "stubbed failure")
        intake.gate_security = lambda c, f, *a, **k: intake.GateResult(
            "G5_security", intake.PASS, "stubbed")
        intake.gate_independent = lambda c, f, *a, **k: intake.GateResult(
            "G6_independent", intake.PASS, "stubbed")
        try:
            integrated, results, detail = intake.process(
                candidate, framework=ROOT, quarantine_dir=self.quarantine,
                snapshot_store=os.path.join(self.tmp, "snaps"))
        finally:
            (intake.gate_functional, intake.gate_security,
             intake.gate_independent) = real

        self.assertFalse(integrated)
        self.assertFalse(os.path.exists(marker),
                         "a failed intake left the candidate applied")
        self.assertTrue(any(r.status == intake.FAIL for r in results))


if __name__ == "__main__":
    unittest.main()
