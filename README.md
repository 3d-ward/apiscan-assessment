# apiscan-assessment

A reusable framework for assessing the security of HTTP/JSON APIs.

It is deliberately *not* a scanner you point at a URL. It is a harness that
takes a declarative description of a target, generates a corpus of test cases
from a documented methodology, executes them under an enforced scope policy,
attributes each response to the layer of the stack that answered it, and
produces a deliverable that states its own limitations.

## Why the layer matters

An HTTP status code is not a verdict. A `400` may come from an edge size limit,
a media-type refusal or application validation. Many APIs answer `200` for
everything and signal the real outcome in the body. So the oracle asks a
different question:

> Which layer refused this request -- and was a refusal what we required?

That gives `expectation x layer -> verdict`, where a verdict is one of
`CONTROL-PRESENT`, `CONTROL-ABSENT`, `OVER-BLOCKED`, `BLOCKED`, `ERROR`,
`OBSERVED` or `UNCLEAR`, with the depth of the control recorded alongside. The
unit of measurement is whether a control exists and how deep it sits.

## What it will not do

* It will not send a request the engagement scope policy has not permitted.
  Scope matches on case *attributes* (`state_mutating`, `volume_class`,
  `payload_class`), so a newly written mutating case is denied by default rather
  than slipping through a stale exclusion list. The gate lives in the transport,
  which cannot be constructed without a policy -- so no command reaches the
  network around it, readiness checks included.
* It will not send anything at all under the default policy. `DEFAULT_DENY`
  covers `state_mutating`, `volumetric`, `destructive`, `infrastructure_pivot`,
  `bulk_extraction`, `injection`, `oversize` and `malformed`. A run needs a
  recorded authorisation, and an authorisation is a named person, a date and a
  retrievable reference.
* It will not disable certificate verification for you. Verification is on by
  default, a configured CA file that does not exist is a hard failure rather
  than a quiet downgrade, and an unverified connection requires
  `tls_verify.mode: "insecure"` written in the profile -- which is then reported
  as a limitation of the run.
* It will not let a response body rewrite its own verdict. Headers and body are
  parsed from separate streams, and stored evidence declares the length of each
  section, so a body containing a forged `HTTP/1.1 200 OK` line changes nothing.
* It will not count a blocked, skipped or never-reached case as a pass. An
  unreached test is not evidence about the control it was meant to probe.
* It will not publish an automated verdict as a confirmed defect. Machine
  findings are `UNRESOLVED` at `suspected` confidence, with the alternative
  explanations a reviewer has to rule out. Promotion to `DEFECT` requires
  reproducing it.
* It will not issue a report without a statement of what the assessment did
  *not* establish, nor one whose defects lack an expectation, an observation, a
  working baseline, evidence and the alternatives considered.
* It will not let the target inject a formula into the client's spreadsheet. A
  cell beginning `=`, `+`, `-` or `@` is neutralised at the renderer boundary.
* It will not write client data into its own tree. The path guard refuses it,
  symlinks included, and a case id is validated before it becomes a filename.
* It will not claim a capability works when its dependency is missing. It
  reports `NOT VERIFIED` and the install command; `apiscan version` lists what
  the current host can actually do.

## Commands

<!-- BEGIN GENERATED COMMAND TABLE -->

| Command | Sends traffic | Writes files | Scope policy | What it does |
|---|---|---|---|---|
| `capture` | no | yes | optional | render PoC evidence from stored bytes |
| `commands` | no | no | optional | print this table, which is the authoritative one |
| `generate` | no | yes | optional | build the corpus and show what it would send; send nothing (writes files only with --out) |
| `init-engagement` | no | yes | optional | scaffold an engagement workspace outside the framework |
| `plan` | no | yes | **required** | write the reviewable test plan a live run would execute |
| `preflight` | **YES** | yes | **required** | readiness gate; sends a small number of gated probes unless --offline |
| `purge` | no | yes | optional | delete evidence past its retention date (dry run unless --force) |
| `reclassify` | no | yes | optional | re-judge a stored run from captured bytes; send nothing |
| `redact` | no | yes | optional | write a redacted copy of a run for distribution; the raw originals are left unmodified |
| `report` | no | yes | optional | build the deliverable from one named run |
| `scan` | **YES** | yes | **required** | execute the corpus and capture evidence |
| `snapshot` | no | yes | optional | snapshot or roll back the framework source |
| `tls-posture` | **YES** | yes | **required** | transport-layer posture; always captured DIRECT |
| `validate` | no | no | optional | validate the profile and scope policy; send nothing |
| `verify` | no | no | optional | re-hash a run against its evidence manifest |
| `version` | no | no | optional | version, commit, environment and optional-dependency status |

Generated from `automation/cli/main.py:COMMANDS` by `apiscan commands --markdown`. Do not edit by hand; the test suite regenerates and compares it.
<!-- END GENERATED COMMAND TABLE -->

## Three modes

`--mode` defaults to `limited-live`, so an omitted flag narrows a run rather
than widening it.

| Mode | Sends | Requires a named subset | Refuses outright, whatever the policy says |
|---|---|---|---|
| `offline-review` | nothing; produces a reviewable test plan | no | everything |
| `limited-live` | a named subset under hard ceilings | **yes** | volumetric, destructive, infrastructure_pivot, bulk_extraction, oversize, injection |
| `active` | the corpus, within the agreed scope | no | nothing |

A mode's refusals are applied in the gate before authorisations are consulted,
and no authorisation lifts them. `limited-live` also caps case count, duration
and response size, enforces a minimum delay between requests, and stops the run
on repeated server errors or sustained latency. Operator flags only ever tighten
those ceilings.

## Quick start

```bash
./apiscan init-engagement ~/engagements/example     # outside this tree
cd ~/engagements/example && $EDITOR profile.json scope-policy.json .env
set -a; . ./.env; set +a
E=~/engagements/example

# Offline. Sends nothing. The plan is what you show a client for approval:
# destination, identities, request count, and every operation that may
# change data.
./apiscan validate --profile $E/profile.json --scope $E/scope-policy.json
./apiscan plan     --profile $E/profile.json --scope $E/scope-policy.json

# Readiness, then the run. Both send traffic, both pass the scope gate.
# --mode defaults to limited-live: a named subset under hard ceilings.
./apiscan preflight --profile $E/profile.json --scope $E/scope-policy.json \
                    --evidence $E/evidence
./apiscan scan --profile $E/profile.json --scope $E/scope-policy.json \
               --evidence $E/evidence --endpoint <id> --families B

# Offline again. Name the run: defaulting to "whatever ran last" is how a
# deliverable gets built from a two-observation TLS check.
./apiscan report --evidence $E/evidence --run <run-id> --out $E/reports \
                 --not-established $E/limits.txt --scope-note "..."

# Raw evidence contains credentials -- the trace files hold every request
# header. Share only a redacted copy; the originals are never modified.
./apiscan redact --evidence $E/evidence --run <run-id> \
                 --profile $E/profile.json --out $E/shareable
```

## Methodology

Seven phases, ordered so that state mutation increases monotonically -- a run
can stop at any boundary and everything executed so far was the less invasive
work:

| Phase | Question | OWASP API |
|---|---|---|
| P1 | Can the wrong role perform a privileged action? | API5 |
| P2 | Can an invalid or mismatched credential authenticate? | API2 |
| P3 | Are identifiers validated against each other? | API1 |
| P4 | Can a caller assert a business outcome they do not control? | API6 |
| P5 | Do undeclared properties bind to domain objects? | API3 |
| P6 | Does every endpoint behave consistently? | API8 |
| P7 | Is trust derived from client-controlled data? | API7/API8 |

Plus ten payload-tamper families (A-J) covering identifier substitution, state
contradiction, injection, type confusion, structural abuse, resource limits,
identifier integrity and replay, media type, HTTP method, and credential and
header tampering.

See `docs/METHODOLOGY.md`.

## Requirements

Core loop: CPython 3.9+ and `curl`. Nothing else is required. Release-tested on
3.9 through 3.13 on Linux and macOS; Windows is exercised in CI and is
best-effort (POSIX file modes do not apply there, so the evidence restriction
that protects captured credentials cannot be enforced -- the manifest records
that rather than implying otherwise). See `RELEASE.md`.

Optional, each degrading gracefully: `openpyxl` (workbook), `Pillow` (embedded
PoC images), Chrome/Chromium (PNG rendering), `pyobjc-framework-Quartz` (proxy
window capture, macOS), `nmap` or `testssl.sh` (cipher enumeration). See
`dependencies/README.md`.

## Tests

```bash
python3 -m unittest discover -s tests -t . -p "test_*.py"
```

Unit, integration (against a loopback mock that is deliberately wrong in
controlled ways), regression (differential testing of the oracle against a
reference implementation) and security hygiene. No test performs outbound
network access.

## Documentation

| Document | Purpose |
|---|---|
| **`docs/WORKFLOW.md`** | **the authoritative workflow. Start here; the others defer to it** |
| `CLAUDE.md` | operating instructions, including for an AI assistant |
| `RELEASE.md` | the release process, and what a release must publish |
| `docs/ARCHITECTURE.md` | components, data flow, design decisions |
| `docs/SETUP.md` | installation and environment |
| `docs/USAGE.md` | running an engagement end to end |
| `docs/METHODOLOGY.md` | phases, families, and why each exists |
| `docs/CONTINUOUS-IMPROVEMENT.md` | how validated improvements are integrated |
| `docs/KNOWN-LIMITATIONS.md` | what this framework does not do |
| `docs/EXTRACTION-COVERAGE.md` | what was reconstructed, partially reconstructed or replaced |
| `docs/capability-registry.json` | the 49 capabilities and where each now lives |
| `governance/improvement-policy.md` | the gates an improvement must pass |

## Licence

MIT -- see [LICENSE](LICENSE). Use it, modify it, build on it; keep the
copyright notice, and note that it is provided with no warranty of any kind.

## Authorised use only

This is a penetration testing tool. **Nothing in this repository authorises you
to send traffic to anything.** Authorisation, scope and target details come from
an engagement directory that you supply and that lives outside this tree; the
scope policy defaults to deny, and a profile naming a host is not permission to
reach it.

Testing a system you do not own, without the written permission of whoever does,
is unlawful in most jurisdictions. That obligation is yours. The licence
disclaims warranty and liability precisely because the tool cannot know whether
your engagement is authorised -- only you can.

## Provenance

Reconstructed from an earlier single-client assessment harness by controlled
extraction: capabilities were reimplemented generically, and no client data,
credential, identifier, hostname or evidence artifact was carried across. Every
example value in this tree is synthetic, using RFC 2606 reserved domains and
RFC 5737 documentation addresses.
