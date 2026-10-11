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
  than slipping through a stale exclusion list.
* It will not count a blocked or skipped case as a pass. An unreached test is
  not evidence about the control it was meant to probe.
* It will not issue a report without a statement of what the assessment did
  *not* establish.
* It will not write client data into its own tree. The path guard refuses it.
* It will not claim a capability works when its dependency is missing. It
  reports `NOT VERIFIED` and the install command.

## Quick start

```bash
./apiscan init-engagement ~/engagements/example     # outside this tree
cd ~/engagements/example && $EDITOR profile.json scope-policy.json .env
set -a; . ./.env; set +a

./apiscan validate  --profile ~/engagements/example/profile.json
./apiscan preflight --profile ~/engagements/example/profile.json \
                    --evidence ~/engagements/example/evidence
./apiscan scan      --profile ~/engagements/example/profile.json \
                    --scope   ~/engagements/example/scope-policy.json \
                    --evidence ~/engagements/example/evidence
./apiscan report    --evidence ~/engagements/example/evidence \
                    --out ~/engagements/example/reports \
                    --not-established ~/engagements/example/limits.txt
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

Core loop: Python 3.8+ and `curl`. Nothing else is required.

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
| `CLAUDE.md` | operating instructions, including for an AI assistant |
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
