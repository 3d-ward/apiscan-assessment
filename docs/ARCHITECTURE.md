# Architecture

## Data flow

```
 target profile (JSON)          scope policy (JSON)
        |                              |
        v                              v
  profile loader  ------------->  ScopePolicy
  (schema + secret refusal)            |
        |                              |
        v                              |
   generators  -->  Corpus  ----->  scope gate  (denied cases are RECORDED,
   families A-J                         |        not silently dropped)
   phases P1-P7                         v
   retest / followup                Transport (curl)
                                        |
                                        v
                                 EvidenceStore  (req / resp / trace,
                                        |        SHA-256 manifest)
                                        v
                                layer attribution
                                        |
                                        v
                              expectation x layer
                                        |
                                        v
                                    verdict + detectors
                                        |
                                        v
                        Register (DEFECT / UNRESOLVED / CONTROL)
                                        |
                                        v
                             Coverage (honesty gates)
                                        |
                                        v
                        ReportModel -> markdown / csv / xlsx
```

## Components

### `framework/core`
Transport, authentication providers, header mutation, profile loading, a
minimal JSON-Schema validator, the path guard and the error hierarchy.

`curl` is used rather than an HTTP library for three assessment-specific
reasons: `--trace-ascii` records the wire exchange including the TLS handshake;
`--data-binary @file` sends the body byte-for-byte so malformed input is not
repaired in transit; and requests traverse a proxy exactly as a browser would.
It also means the core loop has no third-party runtime dependency.

### `framework/oracle`
The analytic core. `layers.py` attributes a response to the layer that answered
it; `verdict.py` maps an expectation against that layer; `envelope.py` decodes
application envelopes for APIs that answer `200` for everything;
`detectors.py` runs data-driven disclosure and reflection rules.

Attribution precedence: transport failure, then edge block, then the profile's
status map, then envelope refinement, then business markers. Edge block comes
early because a request stopped before the application was never actually
tested.

### `framework/corpus`
The case model and generators. Generators mutate payloads **by declared path**
rather than by known structure, which is what makes one generator work against
any API the profile describes.

### `framework/governance`
Scope enforcement by case attribute, with authorisation records that name who
approved what, when, and against which reference.

### `framework/findings` and `framework/reporting`
The register separates confirmed defects from unprovable ones and from controls
that held. Coverage computes what was and was not established. The report model
is plain data; renderers consume it, so the deliverable degrades to Markdown
rather than failing when `openpyxl` is absent.

## Design decisions

1. **The profile is the only coupling point.** No module holds a target
   constant; a security test asserts this.
2. **The oracle is data-driven.** Status map, envelope spec and detector rules
   are configuration, so a new API is *described*, not coded.
3. **Scope matches attributes, not ids.** The predecessor listed excluded case
   ids in a separate file; adding a case meant the list silently fell out of
   date, in the dangerous direction.
4. **Defaults fail safe.** `state_mutating` defaults to true; history markers
   default off; excluded scope needs a recorded authorisation.
5. **Optional dependencies degrade, never crash.** And the degradation is
   reported, never silent.
6. **Provenance is structural.** `CaptureMethod` travels with every evidence
   record into filename, footer and report.
7. **Engagement separation is enforced, not documented.** The path guard
   refuses an output root inside the framework, resolving symlinks first.

## Testing strategy

* **unit** -- pure logic: schema, header mutation, path handling, oracle,
  detectors, scope, evidence integrity, register, coverage, renderers.
* **integration** -- the full pipeline against a loopback mock that is wrong in
  *controlled* ways, plus the same mock in strict mode to prove the scanner does
  not invent findings against a clean target.
* **regression** -- differential testing of the oracle against an independent
  reference implementation of the original semantics, with the two intentional
  divergences pinned.
* **security** -- hygiene of the framework itself.

No test performs outbound network access. The mock binds to `127.0.0.1` on an
ephemeral port and resolves no names.
