# Changelog

Format: each entry records what changed, whether it is an EXTRACTED CAPABILITY
(reconstructed from previously used implementation) or an ENGINEERING
IMPROVEMENT (new work), the capability ids touched, test results, validation
status, and the snapshot to roll back to.

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
