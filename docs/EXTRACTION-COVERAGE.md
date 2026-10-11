# Extraction coverage report

Version 1.1.0  |  2026-10-09

How much of the predecessor's capability survived reconstruction, and what did
not.

## Headline

| Measure | Value |
|---|---|
| Capabilities discovered | 49 |
| Fully reconstructed | 38 (77.6%) |
| Partially reconstructed | 5 (10.2%) |
| Replaced with an equivalent | 1 (2.0%) |
| **Not reconstructed** | **5 (10.2%)** |
| **Accounted for** | **49/49 (100%)** |

Every one of the 49 has a recorded disposition in
`docs/capability-registry.json`.

### Correction, 2026-10-09

Version 1.0.0 of this report claimed 42 of 42, 100% reconstructed. That figure
was wrong — not because a capability was misreported, but because the
enumeration itself was short. A later line-by-line diff of the predecessor
against this framework found **seven capabilities that were never counted**,
now recorded as CAP-043..CAP-049.

The 42 that were enumerated were described accurately. The claim that broke
was "no capability was silently omitted", and the honest restatement is
**42 of 49 carried over**. A framework whose purpose is to stop assessments
quietly overstating themselves does not get to overstate itself, so the
denominator is corrected here rather than in a footnote.

The seven, in rough order of what they cost an engagement:

| | Capability | Why it matters |
|---|---|---|
| CAP-043 | Client-certificate readiness checks | An mTLS target blocks on day one and the preflight gate has nothing to say about it |
| CAP-047 | Client issue-log annotation | On a retest, the annotated client workbook *is* the deliverable |
| CAP-048 | Re-validation verdict vocabulary | No way to grade a prior finding as fixed / partially fixed / open |
| CAP-049 | Target profile importer | Profiles are hand-written; the largest per-engagement setup cost |
| CAP-044 | Proxy CA trust bootstrap from the CLI | Implemented but unreachable, so strict CA verification is not practically available |
| CAP-045 | Untrusted client-certificate generation | Without it the chain-validation positive control cannot run |
| CAP-046 | Multi-path transport enforcement sweep | One probed URL does not evidence a uniformly applied edge control |

## By stage

| Stage | Capabilities | Fully reconstructed | Not reconstructed |
|---|---|---|---|
| Environment preparation | 7 | 5 | 1 |
| Target modelling | 3 | 2 | 1 |
| Corpus generation | 5 | 5 |  |
| Execution | 7 | 4 | 1 |
| Oracle / classification | 7 | 7 |  |
| Evidence capture | 2 | 2 |  |
| PoC production | 7 | 5 |  |
| Consolidation | 3 | 3 |  |
| Reporting | 4 | 2 | 1 |
| Re-validation | 4 | 3 | 1 |
| **Total** | **49** | **38** | **5** |

Two different causes sit behind the shortfalls. The partial reconstructions in
PoC production and reporting trace to optional dependencies unavailable under a
no-download constraint. The five *not reconstructed* entries do not: they were
simply missed by the original enumeration, and each one is work still to do.

## Partially reconstructed

### CAP-018 Window-scoped screenshot capture
Shipped with window-selection logic unit-tested against synthetic window lists
(largest layer-0 window of the named owner, ignoring dialogs, overlays and other
applications, handling negative-origin displays). The runtime path needs
`pyobjc-framework-Quartz`, which is absent. Status: **NOT VERIFIED**, macOS
only. Install: `python3 -m pip install pyobjc-framework-Quartz`.

### CAP-026 TLS and certificate posture
Certificate revocation inspection (CRL distribution point, OCSP, AIA) and
negotiated-parameter capture are implemented on `openssl`, which is present.
Cipher enumeration needs `nmap` or `testssl.sh`. Whether either is present is a
property of the host you run from, not of this repository -- run
`apiscan preflight` and read the `deps.tls` check. When both are absent the
path returns NOT VERIFIED with a remedy rather than a clean result.

### CAP-032 Workbook report generator
Four sheets are produced and verified by reading the workbook back. Embedding
PoC images needs `Pillow`, which is absent; the absence is detected and reported
in the render result, and image paths are referenced instead. That degradation
behaviour *is* tested.

## Replaced

### CAP-019 Proxy GUI automation
The predecessor drove a Java/Swing proxy UI with synthetic mouse and keyboard
events to select a history row before capture. It was **not** reimplemented, and
that is a deliberate decision rather than a gap.

It was inherently brittle -- coordinates calibrated to one proxy version and
theme, defeated by a window resize -- and the problem it solved (selecting the
right history row) is solved more reliably by the deterministic URL markers in
`tools/proxy/markers.py`. The hard-won operational knowledge is preserved in
documentation and in the design of the replacement: history search matches the
URL not the body; sort order is not reliably newest-first; interception can be
toggled on by accident, which is why a health guard runs before each capture.

Consequence: proxy-UI screenshots must be taken manually when a report needs the
proxy interface itself. Rendered evidence (CAP-016) is the primary path, is
portable, needs no screen-recording consent, and cannot capture anything other
than the evidence.

## Capabilities gained

Not present in the predecessor, and recorded as ENGINEERING IMPROVEMENT rather
than as extracted work:

* evidence integrity -- per-artifact SHA-256 manifest with tamper detection
* structural capture provenance carried into filename, footer and report
* scope matching by case attribute, closing the stale-exclusion-list gap
* report issuance gate requiring a statement of what was not established
* mechanised coverage-gap detection for closure runs
* proxy-fidelity verification generalised to a direct-versus-proxied comparison
* literal-secret refusal in the profile loader
* path guard preventing engagement data inside the framework
* markdown and CSV renderers so reporting degrades instead of failing
* detector coverage extended to .NET, Node, PHP, Go, Ruby and cloud metadata
* encoded-variant reflection detection
* snapshot/rollback and a gated improvement-intake process
* differential testing of the oracle against a reference implementation
* socket-level proof that the test suite performs no outbound connection

## Functional coverage

284 tests across unit, integration, regression and security, all passing. The
suite is the authority on this number: run

    python3 -m unittest discover -s tests -t . -p "test_*.py"

## Known gaps

`docs/KNOWN-LIMITATIONS.md` is the authoritative list. In summary: JSON bodies
only; no stateful sequencing; header/bearer/basic authentication only; heuristic
layer attribution; detectors read response bodies only; no CVSS vectors;
narrative report text is authored per engagement.
