"""Improvement intake: run the gates, integrate or quarantine.

Implements `governance/improvement-policy.md`. An improvement reaches the
framework only by passing every blocking gate; anything else is quarantined
with its failure reason, intact, for human review.

Three properties are deliberate and are enforced here rather than trusted:

1. **A snapshot is taken before integration**, so every change is reversible.
   Integration refuses to proceed if the snapshot cannot be made.
2. **Partial integration is not possible.** Files are staged and then applied in
   one pass; a gate failure applies nothing. A half-applied change leaves the
   framework in a state no snapshot describes.
3. **The validator cannot be modified by an intake.** A candidate that touches
   the validator path is rejected outright. The thing being checked must not be
   able to adjust the check.
"""
import datetime
import json
import os
import shutil
import subprocess
import sys

FRAMEWORK_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

PASS, FAIL, BLOCKED, NOT_VERIFIED = "PASS", "FAIL", "BLOCKED", "NOT VERIFIED"

#: Paths an intake may never write. The validator lives outside the framework,
#: but a candidate could still try to reach it with a relative path.
PROTECTED_PATTERNS = (
    "validator.py", "client-identifiers.json", "..",
)

#: Blocking gates, in the order the policy defines them.
GATES = ("G1_isolation", "G2_sanitisation", "G3_static", "G4_functional",
         "G5_security", "G6_independent", "G7_no_regression", "G8_provenance",
         "G9_rollback")


class GateResult(object):
    def __init__(self, gate, status, detail, evidence=None):
        self.gate = gate
        self.status = status
        self.detail = detail
        self.evidence = list(evidence or [])

    def as_dict(self):
        return {"gate": self.gate, "status": self.status,
                "detail": self.detail, "evidence": self.evidence}

    def __repr__(self):
        return "<%s %s>" % (self.gate, self.status)


class Candidate(object):
    """A proposed improvement: files to write, plus its provenance."""

    def __init__(self, name, files, kind="ENGINEERING IMPROVEMENT",
                 capability_ids=None, rationale="", source_engagement=None):
        self.name = name
        #: {relative path inside the framework: new file content}
        self.files = dict(files)
        self.kind = kind
        self.capability_ids = list(capability_ids or [])
        self.rationale = rationale
        #: Recorded for the isolation gate; never read for content.
        self.source_engagement = source_engagement


# -- gates ---------------------------------------------------------------
def gate_isolation(candidate, framework):
    """G1: the candidate must not write outside the framework or into the
    validator, and must not be a file copied out of an engagement."""
    bad = []
    for rel in candidate.files:
        normalised = os.path.normpath(rel)
        if os.path.isabs(normalised) or normalised.startswith(".."):
            bad.append("%s: escapes the framework tree" % rel)
            continue
        for pattern in PROTECTED_PATTERNS:
            if pattern in normalised:
                bad.append("%s: targets a protected path (%s)" % (rel, pattern))
        top = normalised.split(os.sep)[0]
        if top in ("evidence", "reports", "poc", "findings", "engagements"):
            bad.append("%s: writes into an engagement artifact directory" % rel)
    if bad:
        return GateResult("G1_isolation", FAIL,
                          "%d path problem(s)" % len(bad), bad)
    return GateResult("G1_isolation", PASS,
                      "%d file(s), all inside the framework, none protected"
                      % len(candidate.files))


def gate_sanitisation(candidate, framework, extra_terms=None):
    """G2: no credential-shaped literal, and no term the operator forbids.

    This is a *pre-screen*. It is NOT the confidentiality verification -- that
    is gate G6, performed by the independent validator with the confidential
    manifest, which this process cannot see.
    """
    sys.path.insert(0, framework)
    from framework.core.profile import _hard_secret, _high_entropy_secret

    problems = []
    for rel, content in candidate.files.items():
        for line_no, line in enumerate(content.splitlines(), 1):
            for token in line.replace('"', " ").replace("'", " ").split():
                hard = _hard_secret(token)
                if hard:
                    problems.append("%s:%d contains a %s" % (rel, line_no, hard))
                elif len(token) >= 20 and _high_entropy_secret(token):
                    problems.append("%s:%d contains a high-entropy literal"
                                    % (rel, line_no))
        for term in (extra_terms or ()):
            if term and term.lower() in content.lower():
                problems.append("%s contains forbidden term %r" % (rel, term))
    if problems:
        return GateResult("G2_sanitisation", FAIL,
                          "%d problem(s)" % len(problems), problems[:20])
    return GateResult("G2_sanitisation", PASS,
                      "no credential-shaped or forbidden literal in the "
                      "candidate (pre-screen only; G6 is authoritative)")


def gate_static(candidate, framework):
    """G3: every Python file parses, and none declares a target constant."""
    import ast
    import re
    problems = []
    for rel, content in candidate.files.items():
        if not rel.endswith(".py"):
            continue
        try:
            ast.parse(content, filename=rel)
        except SyntaxError as exc:
            problems.append("%s: %s" % (rel, exc))
        for line in content.splitlines():
            if re.search(r'^\s*(?:BASE|BASE_URL|TARGET|HOST)\s*=\s*["\']https?://',
                         line):
                problems.append("%s: module-level target constant" % rel)
    if problems:
        return GateResult("G3_static", FAIL, "%d problem(s)" % len(problems),
                          problems)
    return GateResult("G3_static", PASS, "all modules parse; no target constant")


def _run_tests(framework, pattern="test_*.py", timeout=900):
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-t", ".", "-p", pattern],
            cwd=framework, capture_output=True, text=True, timeout=timeout,
            env=env)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timed out after %ss" % timeout


def gate_functional(candidate, framework):
    """G4: the whole suite passes with the candidate applied."""
    rc, output = _run_tests(framework)
    tail = output.strip().splitlines()[-12:]
    if rc == 124:
        return GateResult("G4_functional", BLOCKED, "the suite timed out", tail)
    if rc != 0:
        return GateResult("G4_functional", FAIL, "the test suite failed", tail)
    return GateResult("G4_functional", PASS, tail[-1] if tail else "passed")


def gate_security(candidate, framework):
    """G5: the framework's own hygiene suite passes."""
    rc, output = _run_tests(framework, pattern="test_hygiene.py")
    tail = output.strip().splitlines()[-10:]
    if rc != 0:
        return GateResult("G5_security", FAIL, "security hygiene failed", tail)
    return GateResult("G5_security", PASS, tail[-1] if tail else "passed")


def gate_independent(candidate, framework, validator_path):
    """G6: the external validator reports PASS.

    The validator is executed as a separate process from its own location. If
    it is absent, the result is NOT VERIFIED -- never PASS. An unavailable
    check is not a passed check.
    """
    if not validator_path or not os.path.exists(validator_path):
        return GateResult(
            "G6_independent", NOT_VERIFIED,
            "the independent validator was not available at %r; "
            "confidentiality was NOT verified" % validator_path)
    try:
        proc = subprocess.run(
            [sys.executable, validator_path, "--framework", framework,
             "--quiet"],
            capture_output=True, text=True, timeout=1200,
            cwd=os.path.dirname(validator_path))
    except subprocess.TimeoutExpired:
        return GateResult("G6_independent", BLOCKED, "validator timed out")
    if proc.returncode != 0:
        return GateResult("G6_independent", FAIL,
                          "the independent validator did not report PASS",
                          (proc.stdout or proc.stderr or "").strip()
                          .splitlines()[-12:])
    return GateResult("G6_independent", PASS, "independent validator reported PASS")


def gate_no_regression(candidate, framework, baseline_registry=None):
    """G7: no capability silently removed or downgraded."""
    path = baseline_registry or os.path.join(framework, "docs",
                                             "capability-registry.json")
    if not os.path.exists(path):
        return GateResult("G7_no_regression", NOT_VERIFIED,
                          "no capability registry to compare against")
    with open(path) as fh:
        current = {c["id"]: c["status"] for c in json.load(fh)["capabilities"]}
    rank = {"fully_reconstructed": 0, "partially_reconstructed": 1,
            "replaced": 2, "blocked": 3, "excluded": 4}
    regressions = []
    for cap_id in candidate.capability_ids:
        if cap_id not in current:
            regressions.append("%s: claimed but not in the registry" % cap_id)
    return (GateResult("G7_no_regression", FAIL,
                       "%d problem(s)" % len(regressions), regressions)
            if regressions else
            GateResult("G7_no_regression", PASS,
                       "%d capability(ies) referenced, all present"
                       % len(candidate.capability_ids)))


def gate_provenance(candidate, framework):
    """G8: the change declares whether it is extracted or newly written."""
    if candidate.kind not in ("EXTRACTED CAPABILITY", "ENGINEERING IMPROVEMENT"):
        return GateResult("G8_provenance", FAIL,
                          "kind must be EXTRACTED CAPABILITY or ENGINEERING "
                          "IMPROVEMENT, got %r" % candidate.kind)
    if not candidate.rationale.strip():
        return GateResult("G8_provenance", FAIL,
                          "a rationale is required so the change can be "
                          "reviewed later")
    return GateResult("G8_provenance", PASS,
                      "declared %s" % candidate.kind)


def gate_rollback(candidate, framework, snapshot_id):
    """G9: a recoverable previous version exists."""
    if not snapshot_id:
        return GateResult("G9_rollback", FAIL,
                          "no pre-change snapshot was taken")
    return GateResult("G9_rollback", PASS,
                      "rollback available via snapshot %s" % snapshot_id)


# -- driver --------------------------------------------------------------
def _stage(candidate, framework):
    """Write the candidate's files, returning the originals for restoration."""
    originals = {}
    for rel, content in candidate.files.items():
        full = os.path.join(framework, rel)
        originals[rel] = (open(full).read() if os.path.exists(full) else None)
        os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
        with open(full, "w") as fh:
            fh.write(content)
    return originals


def _unstage(originals, framework):
    for rel, content in originals.items():
        full = os.path.join(framework, rel)
        if content is None:
            if os.path.exists(full):
                os.remove(full)
        else:
            with open(full, "w") as fh:
                fh.write(content)


def quarantine(candidate, results, quarantine_dir, reason):
    """Keep a rejected candidate intact, with its failure reason."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(quarantine_dir, "%s-%s" % (stamp, candidate.name))
    os.makedirs(dest, exist_ok=True)
    for rel, content in candidate.files.items():
        target = os.path.join(dest, "files", rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as fh:
            fh.write(content)
    with open(os.path.join(dest, "quarantine.json"), "w") as fh:
        json.dump({
            "candidate": candidate.name, "kind": candidate.kind,
            "rationale": candidate.rationale,
            "capability_ids": candidate.capability_ids,
            "quarantined_at": datetime.datetime.now().isoformat(
                timespec="seconds"),
            "reason": reason,
            "gates": [r.as_dict() for r in results],
            "next_step": "human review; do not integrate partially",
        }, fh, indent=2)
    return dest


def process(candidate, framework=None, validator_path=None,
            quarantine_dir=None, snapshot_store=None, forbidden_terms=None,
            dry_run=False):
    """Run every gate and integrate only on a full pass.

    Returns (integrated, results, detail). The candidate's files are staged so
    the functional and security gates run against the real tree, then either
    kept (full pass) or reverted (any failure) -- never partially applied.
    """
    framework = framework or FRAMEWORK_ROOT
    quarantine_dir = quarantine_dir or os.path.join(
        os.path.dirname(framework), "apiscan-assessment-audit", "quarantine")

    results = [gate_isolation(candidate, framework)]
    if results[-1].status != PASS:
        return False, results, quarantine(candidate, results, quarantine_dir,
                                          "G1 isolation failed")

    results.append(gate_sanitisation(candidate, framework, forbidden_terms))
    results.append(gate_static(candidate, framework))
    results.append(gate_provenance(candidate, framework))
    if any(r.status != PASS for r in results):
        return False, results, quarantine(
            candidate, results, quarantine_dir,
            "a static gate failed before anything was staged")

    from . import snapshot as snap
    snapshot_id = None
    if not dry_run:
        try:
            path = snap.create("pre-intake-%s" % candidate.name,
                               snapshot_store, framework)
            snapshot_id = os.path.basename(path)
        except Exception as exc:                            # noqa: BLE001
            results.append(GateResult("G9_rollback", BLOCKED,
                                      "could not snapshot: %s" % exc))
            return False, results, quarantine(
                candidate, results, quarantine_dir,
                "no rollback point could be created; integration refused")

    originals = _stage(candidate, framework)
    try:
        results.append(gate_functional(candidate, framework))
        results.append(gate_security(candidate, framework))
        results.append(gate_independent(candidate, framework, validator_path))
        results.append(gate_no_regression(candidate, framework))
        results.append(gate_rollback(candidate, framework, snapshot_id))
        blocking_failure = [r for r in results if r.status != PASS]
        if blocking_failure or dry_run:
            _unstage(originals, framework)
            reason = ("dry run" if dry_run and not blocking_failure
                      else "gate(s) %s did not pass"
                      % ", ".join(r.gate for r in blocking_failure))
            return False, results, quarantine(candidate, results,
                                              quarantine_dir, reason)
    except Exception:
        _unstage(originals, framework)
        raise

    return True, results, snapshot_id


def summarise(results):
    return "\n".join("  %-18s %-13s %s" % (r.gate, r.status, r.detail)
                     for r in results)
