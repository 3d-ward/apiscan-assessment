# Release process

ENGINEERING IMPROVEMENT (review finding 5: "establish a repeatable release
process"). The review's observation is the one worth keeping in view:

> The existing tests are valuable, but passing tests alone would not establish
> that the scanner's conclusions are correct.

So a release publishes what was actually verified, on what, and what remains
unverified. "The suite is green" is a fact about the suite.

---

## What every release must publish

| Item | Where it comes from |
|---|---|
| Version | `framework/environment.py:VERSION`, asserted against the top of `CHANGELOG.md` by the test suite |
| Commit identifier | `apiscan version` reports it, and marks a modified tree `+modified` |
| Supported environments | `framework/environment.py:SUPPORTED_ENVIRONMENTS` |
| Actual test results | the real numbers from the matrix: counts, skips, and the platform each ran on |
| Known limitations | `docs/KNOWN-LIMITATIONS.md` |
| Optional capabilities absent on the recording host | `apiscan version --json` |

A release note that says "all tests pass" without saying how many, on what, and
what was skipped is not a release note.

---

## Supported environments

CPython 3.9 through 3.13 on Linux and macOS. Windows is exercised in CI and is
**best-effort**: POSIX file modes are not meaningful there, so the evidence
restriction that protects captured credentials cannot be applied -- the
manifest records that rather than implying otherwise. Do not hold client
evidence on Windows without separate filesystem access control.

The core loop needs only the standard library and `curl`. Every optional
dependency degrades to `NOT VERIFIED` rather than to a pass.

---

## The checks

Run locally before proposing a release; CI runs the same things across the
matrix.

```bash
# 1. The whole suite.
python3 -m unittest discover -s tests -t . -p "test_*.py"

# 2. The regression tests for previously reported defects, named so a
#    failure says which weakness came back.
python3 -m unittest tests.regression.test_review_defects

# 3. Documentation has not drifted from the code.
python3 -m unittest tests.regression.test_documentation_matches_code

# 4. Contamination: no client data, no credential literals, reserved
#    hostnames only.
python3 -m unittest tests.security.test_hygiene

# 5. The oracle differential, against an independent reference
#    implementation of the original classification semantics.
python3 -m unittest tests.regression.test_oracle_differential

# 6. What this host can actually do.
./apiscan version --json
```

### Distinguishing an environment gap from a product defect

A test that needs an absent optional dependency must **skip**, not fail. CI has
a dedicated `degraded` job that installs nothing optional and fails if any test
errors rather than skipping -- because a test that fails without `openpyxl` is
indistinguishable, in a bug report, from a real defect.

When triaging a reported failure, ask for `apiscan version --json` first. It
names the version, the commit, the platform, the Python, and every optional
capability with the consequence of its absence.

---

## Second-maintainer review

**Changes touching any of these need review by a second maintainer before
merge**, because a mistake in them is not visible in the output:

| Area | Files | Why |
|---|---|---|
| **Scope** | `framework/governance/` | decides what traffic is permitted to exist |
| **Credentials** | `framework/core/profile.py`, `framework/core/auth.py`, `framework/evidence/redact.py` | decides whether a secret leaves the engagement |
| **Transport** | `framework/core/transport.py` | the only thing that opens a socket; also where TLS verification lives |
| **Verdicts** | `framework/oracle/` | decides what the assessment concludes |
| **Evidence** | `framework/evidence/` | decides whether a finding can be verified later |

The reviewer should be able to answer, for the diff: *could this send a request
that was not authorised, leak a credential, or change a conclusion?*

`tests/regression/test_oracle_differential.py` holds an independent reference
implementation and compares the two across a generated matrix. If a change to
attribution or verdict mapping makes it fail, decide deliberately whether the
change is an improvement, then update the pinned divergence set and document
it. **Do not delete the test to make it pass.**

---

## Steps

1. **Branch.** Never release from an uncommitted tree: `apiscan version` would
   report `+modified` and the commit identifier in the release would be wrong.
2. **Bump** `framework/environment.py:VERSION`.
3. **Write the CHANGELOG entry.** Name each change as EXTRACTED CAPABILITY or
   ENGINEERING IMPROVEMENT, list breaking changes explicitly, and record the
   real test results including skips and the platform. The test suite asserts
   the version appears at the top of the file.
4. **Run the checks above** and paste the actual output into the entry.
5. **Second-maintainer review** if the diff touches scope, credentials,
   transport, verdicts or evidence.
6. **Confirm CI is green across the whole matrix**, including the `degraded`
   and `hygiene` jobs.
7. **Tag** `v<version>` and push.
8. **Snapshot**, so the previous working tree is recoverable outside git:
   `./apiscan snapshot create --label pre-v<version>`.

---

## What a release does NOT establish

State this, every time, rather than letting silence imply the opposite:

* **That the scanner's conclusions are correct.** The suite tests the harness
  against a loopback mock that is wrong in controlled ways. It establishes that
  the oracle classifies that mock as intended. It does not establish that the
  classification is right about any real API, and no test can.
* **That a run is safe against a particular target.** The scope gate enforces
  what the engagement authorised. Whether what was authorised was wise is a
  human judgement.
* **That evidence is complete.** `NOT VERIFIED`, `BLOCKED`, `SKIPPED` and
  `NOT-REACHED` exist because assessments have gaps. A release does not shrink
  them.
* **That the framework holds no client data.** `tests/security/test_hygiene.py`
  checks for credential shapes, non-reserved hostnames and secret files. It
  deliberately does **not** check for any specific client's identifiers --
  embedding such a list would ship the very data the framework exists to keep
  out. That check belongs to the operator's separate, confidential validator,
  which is maintained outside this repository and **must never be modified to
  make a change pass**.
