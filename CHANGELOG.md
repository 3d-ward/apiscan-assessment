# Changelog

Format: each entry records what changed, whether it is an EXTRACTED CAPABILITY
(reconstructed from previously used implementation) or an ENGINEERING
IMPROVEMENT (new work), the capability ids touched, test results, validation
status, and the snapshot to roll back to.

## 1.1.0 -- external review remediation

**Provenance.** ENGINEERING IMPROVEMENT throughout. Addresses an external
review of 1.0.0 by security practitioners. Each item below names the finding it
answers and has a regression test in
`tests/regression/test_review_defects.py`, one test class per finding.

**Breaking changes.** Three, all in the safe direction:

1. `Transport` cannot be constructed without a `scope_policy`.
2. The default scope policy now denies `injection`, `oversize` and `malformed`,
   and `state_mutating` is derived from the HTTP method as well as the case
   annotation -- so a default-scope run against the example corpus permits 4
   read-method cases of 352 rather than 265.
3. A `DEFECT` register entry requires `confidence="reproduced"` or
   `"manually-confirmed"`. An existing register JSON with `DEFECT` rows will
   raise `RegisterError` until the field is added.

Commands gained: `plan`, `redact`, `purge`, `verify`, `commands`, `version`.
`report`, `capture`, `reclassify`, `verify` and `redact` now require `--run` or
an explicit `--latest`.

### Critical -- apply scope checks to every network request

* The scope gate moved from `Runner.run_case` into `Transport`, which refuses
  to be constructed without a policy and refuses to send any request it cannot
  attribute to a permitted case or probe. Preflight's reachability and
  oracle-calibration probes, the proxy forwarding and CA fetches, the
  fidelity comparison and the rate-limit burst all previously reached the
  network without consulting one.
* `preflight` accepts `--scope`, and every networked check declares a probe.
  A denied probe is reported `NOT VERIFIED` and is not sent; a context with no
  policy sends nothing at all.
* `governance.scope.Probe`, `ReadOnlyProbe` and `TransportProbe` give
  non-corpus requests a case-shaped face. An unlabelled request defaults to
  state-mutating and unclassified, which default-deny refuses.
* `modules/rate_limit.probe` accepted a `scope_policy` argument and never read
  it. It now evaluates the burst before any thread starts, and each request
  inside it is gated again by the transport.

### Critical -- HTTPS verification on by default

* `tls_verify.mode` is now `system` (default), `ca` or `insecure`. Verification
  is on unless the profile turns it off in writing.
* A configured CA file that does not exist is a `TransportError`. It previously
  fell back to `-k`, so a mistyped or moved CA path silently weakened every
  request in the run.
* The shipped example profile verifies; `insecure` is reported as a limitation
  of the whole run and merged into the report's "not established" list
  automatically.

### High -- separate response headers from response bodies

* curl writes the header dump and the body to separate files. They previously
  shared stdout and were split by locating the last `^HTTP/\d` line, so a
  response body containing a forged status line became the headers the oracle
  attributed, the detectors scanned and the verdict rested on.
* Stored evidence uses a length-declared envelope (`APISCAN-EVIDENCE/1`), so
  re-judging stored bytes cannot be steered by their content either. Evidence
  written by 1.0.0 still parses, flagged `legacy_format`.
* Both ends open with `newline=""`; universal-newline translation would shift
  every declared offset for CRLF headers. The live-versus-reclassified
  differential test caught this.

### High -- protect captured credentials and personal data

* Run directories are mode 0700, artifacts 0600, and the manifest's `access`
  block records whether the filesystem actually applied it.
* New `framework/evidence/redact.py` and `apiscan redact`: a redacted COPY for
  distribution, leaving the raw originals unmodified so the evidence manifest
  keeps verifying. Removes the profile's resolved `${ENV:...}` values,
  credential headers by name, and credential shapes; `--pii` adds personal
  data shapes.
* Each run records `retention_days` (default 90) and `retain_until`.
  `apiscan purge` enforces it, dry-run unless `--force`.

### High -- validate resolved file destinations

* `pathguard.safe_component`, `safe_join` and `safe_relative_join`. Windows
  separators, drive letters and reserved device names are refused on every
  platform.
* Applied to case ids (validated in `Case.__init__`, where they enter the
  model), evidence paths, run ids, derived artifacts, stored evidence paths
  read back from `results.json`, intake staging and snapshot rollback.
* G1 isolation resolves candidate paths instead of substring-matching them: a
  backslash-separated path is one opaque component to `os.path.normpath` on
  POSIX and escaped on Windows.

### Conservative default mode

* Three engagement modes (`framework/governance/modes.py`):
  `offline-review`, `limited-live` (the default) and `active`. A mode's
  refusals are applied before authorisations are consulted and no
  authorisation lifts them.
* `framework/governance/limits.py`: per-mode ceilings on case count, duration
  and response size, a request-rate floor, and stop conditions for consecutive
  server errors and sustained latency. Operator flags only ever tighten them.
* Cases a stopped run never sent are recorded `NOT-REACHED`, distinct from
  `SKIPPED`; coverage reports `INCOMPLETE`.
* `framework/governance/plan.py` and `apiscan plan`: destination, identities,
  endpoints, request count and every data-changing operation, stated before
  execution. `scan` prints it and asks for confirmation.

### Findings that are harder to misinterpret

* Register entries carry `confidence`, `expected_behaviour`,
  `observed_behaviour`, `baseline_reference`, `alternative_explanations`,
  `limitations` and `state_verification`.
* `promote_machine_findings` produces `UNRESOLVED`/`suspected` rows with
  conditional impact statements and pre-filled alternative explanations. It
  previously published automated verdicts as confirmed defects.
* A report is not issuable while a `DEFECT` row lacks an expectation, an
  observation, a baseline, evidence, a recommendation or alternatives.
* `framework/corpus/generators/verification.py`: state read-back where the
  profile declares one, and ownership cases built only from declared
  `controlled_resources` with recorded provenance -- never guessed
  identifiers.

### Untrusted data

* `framework/reporting/renderers/safe.py` neutralises spreadsheet formula
  injection and Markdown structure injection from target-controlled text.
  Wired into the CSV, XLSX and Markdown renderers.

### One authoritative workflow

* `docs/WORKFLOW.md` is now authoritative. The command table is generated from
  `automation/cli/main.py:COMMANDS` by `apiscan commands --markdown` and
  embedded in `CLAUDE.md`, `README.md` and the skill;
  `tests/regression/test_documentation_matches_code.py` regenerates and
  compares it. CLAUDE.md previously said two commands send traffic while the
  skill correctly listed three.
* The skill activates on the user's task, not on the presence of a
  `profile.json`.

### Release process

* `RELEASE.md`, `.github/workflows/ci.yml` (Linux/macOS/Windows x CPython
  3.9-3.13), `framework/environment.py` and `apiscan version`.

**Test results.** 390 tests. Verified locally on macOS 14 (Darwin 24.6.0,
x86_64):

| Interpreter | Result | Skips | Optional dependencies present |
|---|---|---|---|
| CPython 3.14.6 | OK | 1 | `openpyxl`; `Pillow` and `pyobjc-framework-Quartz` absent |
| CPython 3.11.x | OK | 2 | none (`openpyxl` and `Pillow` both absent) |

The skips are dependency skips, not failures, which is the property the
`degraded` CI job exists to enforce: proxy-window capture needs
`pyobjc-framework-Quartz`, and the workbook image test needs `openpyxl`. A
missing optional dependency must make a test skip, never fail, so that an
environment gap in a bug report is distinguishable from a product defect.

**Not verified locally.** CPython 3.9, 3.10, 3.12 and 3.13, and Linux and
Windows, are covered by `.github/workflows/ci.yml` but were not executed on the
machine that produced this entry -- 3.9, 3.10, 3.12 and 3.13 were not installed
on it. The code contains no syntax newer than 3.9, but that is an inspection,
not a test result. Treat the matrix as verified only once CI has run it.

**Known limitations.** See `docs/KNOWN-LIMITATIONS.md`.

## 1.0.0 -- initial reconstruction

**Provenance.** Reconstructed by controlled extraction from a single-client
assessment harness. No client data, credential, identifier, hostname or evidence
artifact was carried across; capabilities were reimplemented generically and
every example value is synthetic.

### Extracted capabilities
Transport and proxy mediation; multi-identity credential matrix; header mutation;
A-J payload-tamper families; P1-P7 phase model mapped to OWASP API Top 10;
layer-attribution oracle; expectation-to-verdict mapping; application-envelope
decoding; information-disclosure and reflection detectors; blocked-is-not-a-pass
rule; proxy response-splitting correction; structured evidence capture; offline
re-classification; deterministic proxy-history correlation; evidence rendering;
provenance honesty rule; window-scoped screenshot capture; pre-capture proxy
health guard; preflight readiness gate; proxy-fidelity verification; scope
enforcement; state-mutation annotation; non-destructive rate-limit probe; TLS and
certificate posture; re-validation corpus model; matrix-completion closure;
second-order follow-up probes; finding consolidation; severity and CWE taxonomy;
workbook reporting; report structure; coverage and honesty accounting; operator
runbook; blocker-record pattern; engagement target model; single-request CLI;
endpoint-by-identity matrix; proxy CA bootstrap; headline-evidence selection;
authored-plus-machine finding merge.

### Engineering improvements
* **Scope by attribute, not case id.** The predecessor maintained a separate
  list of excluded case ids, so a newly added mutating case was not excluded and
  would be sent unreviewed. Scope now matches `state_mutating`, `volume_class`
  and `payload_class`, with default-deny.
* **`state_mutating` defaults to true.** Forgetting to annotate now denies.
* **Evidence integrity.** Per-artifact SHA-256 manifest, run metadata, and a
  verification routine that detects edits and unlisted files.
* **Structural provenance.** `CaptureMethod` travels with every evidence record
  into filename, footer and report; a direct capture cannot claim a proxy.
* **Layered verdict policy.** A business-layer refusal now satisfies an
  expectation of rejection and records `control_depth`. The predecessor scored
  it as a missing control, which disagreed with the assessor's own judgement and
  was reconciled by hand. `validation_strict` reproduces the old behaviour.
* **404 with an application envelope** is attributed to the application rather
  than to a missing route.
* **Envelope decoding parses JSON by path**, falling back to regex only for a
  malformed body.
* **Detector coverage** extended from Java/Python/SQL to .NET, Node, PHP, Go,
  Ruby, cloud metadata and credential shapes; rules are data.
* **Reflection detection** compares HTML-, URL- and JSON-escaped and case-folded
  variants, not only verbatim.
* **Reporting separated from rendering**, with Markdown and CSV renderers that
  need no third-party package, so the deliverable degrades instead of failing.
* **Report issuance gate.** Mandatory sections, including what the assessment
  did not establish.
* **Mechanised coverage-gap detection** for closure runs.
* **Follow-up probes generalised** into a parameterised library.
* **Proxy-fidelity probes** generalised to a direct-versus-proxied comparison,
  so the check is target-independent, with affected payload classes marked
  unreliable on failure.
* **Preflight as a check registry** with machine-readable output.
* **Proxy health probe** targets the proxy's own control endpoint rather than a
  third-party internet host.
* **Marker correlation** adds a header mode for targets that reject unknown
  query parameters.
* **Rate-limit module** has hard ceilings and a mandatory citability flag.
* **Path guard** structurally prevents engagement data inside the framework.
* **Secret refusal** in the profile loader, with entropy-based detection tuned
  against both false positives and false negatives.
* **Snapshot/rollback** in place of version control.
* **Differential testing** of the oracle against a reference implementation,
  with both intentional divergences pinned.
* **Gated improvement intake** (`automation/maintenance/intake.py`): the nine
  policy gates run as code, a pre-change snapshot is mandatory, partial
  integration is impossible, and a candidate that would write to the validator
  path is rejected outright.
* **Deterministic headline-evidence nomination**, replacing hand-picked PoC
  selection.
* **Socket-level egress proof**: `connect`, `connect_ex` and `getaddrinfo` are
  instrumented during a representative run, so the suite's network isolation is
  evidenced rather than asserted.

### Tests
191 tests: unit, integration (loopback mock, permissive and strict modes),
regression (oracle differential), security hygiene. All pass. One skipped when
`openpyxl` is absent.

### Not verified
Proxy-window capture (`pyobjc-framework-Quartz` absent), workbook image
embedding (`Pillow` absent), TLS cipher enumeration (`nmap`/`testssl.sh`
absent). See `docs/KNOWN-LIMITATIONS.md`.
