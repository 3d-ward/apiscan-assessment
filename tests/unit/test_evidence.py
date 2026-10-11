import os
import shutil
import tempfile
import unittest

from tests.support import FakeResponse, ROOT  # noqa: F401
from framework.core.errors import PathGuardError
from framework.evidence.provenance import (CaptureMethod, filename_suffix,
                                           provenance_line, validate)
from framework.evidence.store import EvidenceStore, find_latest_run


class TestProvenance(unittest.TestCase):
    """Transport-layer evidence cannot be captured through an intercepting
    proxy -- the proxy attaches its own client certificate and the finding
    stops reproducing. Mislabelling that would misrepresent evidence, so the
    rule is enforced by the API shape, not by discipline."""

    def test_proxy_requires_a_proxy_label(self):
        with self.assertRaises(ValueError):
            provenance_line(CaptureMethod.PROXY, "target")

    def test_direct_must_not_claim_a_proxy(self):
        with self.assertRaises(ValueError):
            provenance_line(CaptureMethod.DIRECT, "target", "127.0.0.1:8080")

    def test_valid_lines(self):
        self.assertIn("via proxy", provenance_line(
            CaptureMethod.PROXY, "t", "127.0.0.1:8080"))
        self.assertIn("DIRECT", provenance_line(CaptureMethod.DIRECT, "t"))

    def test_every_method_has_a_distinct_filename_suffix(self):
        suffixes = [filename_suffix(m) for m in CaptureMethod.ALL]
        self.assertEqual(len(suffixes), len(set(suffixes)))

    def test_unknown_method_rejected(self):
        with self.assertRaises(ValueError):
            validate("made-up")


class TestEvidenceStore(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="apiscan-ev-")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def store(self):
        return EvidenceStore(os.path.join(self.root, "evidence"),
                             run_id="20260101-000000",
                             metadata={"target": "synthetic"})

    def test_refuses_a_root_inside_the_framework(self):
        from framework.core.pathguard import FRAMEWORK_ROOT
        with self.assertRaises(PathGuardError):
            EvidenceStore(os.path.join(FRAMEWORK_ROOT, "evidence"))

    def test_manifest_covers_every_artifact(self):
        store = self.store()
        store.write_response("C01", FakeResponse(200, '{"a":1}',
                                                 "HTTP/1.1 200 OK",
                                                 {"curl_rc": 0}))
        with open(store.request_path("C01"), "w") as fh:
            fh.write("{}")
        store.record({"case_id": "C01"})
        manifest = store.finalise()
        names = {a["file"] for a in manifest["artifacts"]}
        self.assertEqual(names, {"C01.req.txt", "C01.resp.txt",
                                 "results.json", "run.json"})
        self.assertEqual(EvidenceStore.verify(store.run_dir), [])

    def test_verify_detects_tampering(self):
        store = self.store()
        store.write_response("C01", FakeResponse(200, "x", "", {"curl_rc": 0}))
        store.finalise()
        with open(os.path.join(store.run_dir, "C01.resp.txt"), "a") as fh:
            fh.write("EDITED")
        problems = EvidenceStore.verify(store.run_dir)
        self.assertEqual(len(problems), 1)
        self.assertIn("hash mismatch", problems[0])

    def test_verify_detects_an_unlisted_file(self):
        store = self.store()
        store.finalise()
        with open(os.path.join(store.run_dir, "extra.txt"), "w") as fh:
            fh.write("x")
        self.assertTrue(any("not in manifest" in p
                            for p in EvidenceStore.verify(store.run_dir)))

    def test_latest_run_pointer(self):
        store = self.store()
        store.finalise()
        self.assertEqual(find_latest_run(store.root), store.run_dir)


if __name__ == "__main__":
    unittest.main()


class TestDerivedArtifacts(unittest.TestCase):
    """A post-run artifact the framework itself writes -- the re-classification
    output -- must not make the run fail its own integrity check.

    ENGINEERING IMPROVEMENT. ``reclassify`` wrote results-reclassified.json
    into the run directory, where ``verify`` reported it as "present but not in
    manifest". Running a documented, read-only command therefore broke evidence
    verification permanently, which is an integrity feature crying wolf on its
    own output. Derived artifacts are now registered and hashed, so tamper
    detection still applies to them.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="apiscan-dv-")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def store(self):
        return EvidenceStore(os.path.join(self.root, "evidence"),
                             run_id="20260101-000000",
                             metadata={"target": "synthetic"})

    def _derived(self, store, name="results-reclassified.json", body='{"a":1}'):
        path = os.path.join(store.run_dir, name)
        with open(path, "w") as fh:
            fh.write(body)
        return path

    def test_an_unregistered_derived_file_still_fails_verification(self):
        store = self.store()
        store.finalise()
        self._derived(store)
        self.assertTrue(any("not in manifest" in p
                            for p in EvidenceStore.verify(store.run_dir)))

    def test_registering_a_derived_artifact_keeps_the_run_verifiable(self):
        store = self.store()
        store.finalise()
        self._derived(store)
        EvidenceStore.register_derived(store.run_dir,
                                       "results-reclassified.json")
        self.assertEqual(EvidenceStore.verify(store.run_dir), [])

    def test_a_derived_artifact_is_recorded_as_derived_not_captured(self):
        store = self.store()
        manifest = store.finalise()
        captured = {a["file"] for a in manifest["artifacts"]}
        self._derived(store)
        updated = EvidenceStore.register_derived(store.run_dir,
                                                 "results-reclassified.json")
        self.assertEqual({a["file"] for a in updated["artifacts"]}, captured,
                         "a derived artifact must not join the captured set")
        self.assertEqual([d["file"] for d in updated["derived"]],
                         ["results-reclassified.json"])
        self.assertIn("registered_utc", updated["derived"][0])

    def test_tampering_with_a_derived_artifact_is_still_detected(self):
        store = self.store()
        store.finalise()
        path = self._derived(store)
        EvidenceStore.register_derived(store.run_dir,
                                       "results-reclassified.json")
        with open(path, "a") as fh:
            fh.write("EDITED")
        problems = EvidenceStore.verify(store.run_dir)
        self.assertEqual(len(problems), 1)
        self.assertIn("hash mismatch", problems[0])

    def test_re_registering_refreshes_rather_than_duplicates(self):
        store = self.store()
        store.finalise()
        path = self._derived(store)
        EvidenceStore.register_derived(store.run_dir,
                                       "results-reclassified.json")
        with open(path, "w") as fh:
            fh.write('{"a":2}')
        updated = EvidenceStore.register_derived(store.run_dir,
                                                 "results-reclassified.json")
        self.assertEqual(len(updated["derived"]), 1)
        self.assertEqual(EvidenceStore.verify(store.run_dir), [])

    def test_registering_a_missing_file_raises(self):
        store = self.store()
        store.finalise()
        with self.assertRaises(FileNotFoundError):
            EvidenceStore.register_derived(store.run_dir, "nope.json")
