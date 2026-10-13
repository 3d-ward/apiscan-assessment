# CLAUDE.md -- operating instructions for apiscan-assessment

## 0. The one thing to understand first

**This repository is reusable infrastructure. It is not a client engagement.**

Nothing here authorises you to test anything. Authorisation, scope and target
details come from an *engagement directory* that lives OUTSIDE this tree and is
supplied by the operator. The existence of a profile file is not permission to
send traffic to the host it names. If you cannot point to a scope policy with a
recorded authorisation, the answer is to ask, not to scan.

Three rules follow from that, and they are enforced in code, not left to care:

1. **No client data in this tree.** Evidence, findings, reports, credentials and
   certificates belong in the engagement directory. The path guard
   (`framework/core/pathguard.py`) refuses any evidence or output root that
   resolves inside this tree, symlinks included.
2. **No target constants in code.** Every host, endpoint, identifier, credential
   and envelope field name is profile data. If you find yourself typing a real
   hostname into a `.py` file, stop: it belongs in the engagement profile.
3. **No secrets in a profile.** Credentials are `${ENV:NAME}` references
   resolved at load time. The loader raises `SecretInProfileError` on a literal,
   because a profile is a config artifact that gets committed and shared.

---

## 1. What this framework does

It assesses the security of an HTTP/JSON API by:

* generating a corpus of test cases from a declarative description of the target
* executing them, optionally through an intercepting proxy, with scope
  enforcement applied before anything is sent
* attributing each response to the layer of the stack that answered it, and
  mapping the declared expectation against that layer to produce a verdict
* capturing hash-manifested evidence for every case
* consolidating results into a findings register, one row per distinct defect
* producing a deliverable that states its own limitations

### The central idea

An HTTP status code is not a verdict. The same `400` may come from an edge size
limit, a media-type refusal or application validation, and many APIs return
`200` for everything and signal the real outcome in the body. So the oracle
attributes each response to the **layer** that answered it, then maps
`expectation x layer -> verdict`. The unit of measurement is *whether a control
exists and how deep it sits*, not pass/fail.

Read `framework/oracle/layers.py` and `framework/oracle/verdict.py` before
changing anything about classification.

---

## 2. Architecture

```
framework/
  core/          transport, auth providers, header mutation, profile loader,
                 JSON-schema validator, path guard, error types
  methodology/   phase definitions (P1-P7 + OWASP mapping), payload taxonomy
  corpus/        case model, payload templating, generators
                   generators/families.py   A-J payload-tamper families
                   generators/phases.py     P1-P7 phase model
                   generators/retest.py     re-validation + closure
                   generators/followup.py   second-order probe library
                   generators/verification.py state read-back + ownership
  oracle/        layer attribution, verdict mapping, envelope decoding,
                 detector rules (data, in oracle/rules/*.json)
  evidence/      evidence store with SHA-256 manifest, capture provenance
                   store.py     length-declared response envelope, mode 0600,
                                retention metadata, kind-aware run discovery
                   redact.py    redacted COPIES for distribution; originals
                                are never modified
  governance/    scope policy (attribute-matched), authorisation records
                   scope.py     the one gate; Probe / ReadOnlyProbe /
                                TransportProbe for non-corpus requests
                   modes.py     offline-review / limited-live / active
                   limits.py    run ceilings and stop conditions
                   plan.py      the pre-execution test plan
  findings/      register (DEFECT/UNRESOLVED/CONTROL), coverage accounting
  reporting/     report model + markdown / csv / xlsx renderers
                   renderers/safe.py  neutralises target-controlled text
                                      (spreadsheet formula injection)
  modules/       rate_limit, tls_posture, response_headers
  runner.py      scope gate -> transport -> evidence -> oracle -> record
  environment.py version, commit, and what THIS host can actually do

tools/
  proxy/         CA bootstrap, health guard, fidelity probes, history markers
  capture/       evidence rendering (html/png), window capture (macOS)

automation/
  preflight/     pluggable readiness checks
  cli/           the apiscan command
  maintenance/   snapshot + rollback

configs/schemas/   target-profile, scope-policy (JSON Schema)
configs/examples/  SYNTHETIC example profile -- never edit in place
tests/             unit / integration / regression / security + loopback mock
```

---

## 3. Commands

`docs/WORKFLOW.md` is the authoritative workflow. The table below is generated
from `automation/cli/main.py:COMMANDS` and checked by
`tests/regression/test_documentation_matches_code.py`; do not edit it by hand.

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

**Three commands send traffic: `scan`, `tls-posture` and `preflight`.** An
earlier version of this file said two, and that was wrong in the direction that
matters: `preflight` sends an empty-body POST to the first endpoint, a
well-formed baseline body, and -- when `fidelity_expectations.enabled` is set --
a 200 KB body, a NUL byte and a truncated JSON document. Readiness checking is
not a licence to send traffic; it is traffic. Every one of those probes is now a
declared `governance.scope.Probe` judged by the policy before it leaves, and a
denied probe is reported `NOT VERIFIED` rather than sent.

`validate`, `generate`, `plan`, `reclassify`, `capture`, `redact`, `verify` and
`report` never emit a request. Use them freely -- `reclassify` does not even
need the credentials resolved, since it re-judges stored bytes.

`tls-posture` is **always DIRECT** -- an intercepting proxy terminates TLS and
presents its own client certificate, so transport evidence captured through one
does not reproduce. Set `require_proxy` in the scope policy and transport probes
will need an explicit `direct_transport` authorisation, which is the intended
friction.

### Engagement modes

Every command that can send takes `--mode`, defaulting to `limited-live`:

| Mode | Sends | Requires a named subset | Refuses outright |
|---|---|---|---|
| `offline-review` | nothing | no | everything |
| `limited-live` | a named subset under hard ceilings | **yes** | volumetric, destructive, infrastructure_pivot, bulk_extraction, oversize, injection |
| `active` | the corpus, within the agreed scope | no | nothing |

A mode's refusals are applied in `ScopePolicy.evaluate` before authorisations
are consulted, and **no authorisation lifts them** (`ScopePolicy.with_mode`,
`framework/governance/modes.py`). A cautious mode that an entry in the same
engagement's policy file could override would be a suggestion, not a safety
property.

`limited-live` also imposes ceilings and stop conditions
(`framework/governance/limits.py`): 40 cases, 600 s, 2 MB per response, 0.5 s
between requests, stop after 3 consecutive server errors or 5 consecutive
responses slower than 10 s. `--max-cases`, `--max-duration-s`,
`--max-response-bytes`, `--delay-s` and `--stop-after-server-errors` only ever
TIGHTEN these -- `RunLimits.replace` clamps rather than grants, so
`--max-cases 10000` in `limited-live` does not quietly become `active`.

Cases a stopped run never sent are recorded `NOT-REACHED`, distinct from
`SKIPPED`, and coverage then reports `INCOMPLETE`. Conflating "the engagement
excluded this" with "we stopped early" would let a run that died on its third
consecutive 500 report the same coverage as a deliberately narrowed one.

## 4. Starting a new engagement

```bash
./apiscan init-engagement ~/engagements/acme-2026   # outside this tree
cd ~/engagements/acme-2026
# 1. edit profile.json      -- describe the target (no secrets)
# 2. edit scope-policy.json -- rules of engagement (default-deny)
# 3. fill .env              -- credentials, mode 0600
set -a; . ./.env; set +a
```

Then, in order. `E=~/engagements/acme-2026` throughout:

```bash
# --- offline: send nothing, produce something a human can approve ---------
./apiscan validate --profile $E/profile.json --scope $E/scope-policy.json
./apiscan generate --profile $E/profile.json --scope $E/scope-policy.json --list
./apiscan plan     --profile $E/profile.json --scope $E/scope-policy.json \
                   --out $E/plan.json

# --- readiness: sends gated probes (or --offline for none) ---------------
./apiscan preflight --profile $E/profile.json --scope $E/scope-policy.json \
                    --evidence $E/evidence

# --- live: prints the plan, then asks before opening a socket ------------
./apiscan scan --profile $E/profile.json --scope $E/scope-policy.json \
               --evidence $E/evidence \
               --mode limited-live --endpoint <id> --families B

# --- afterwards: all offline, and all requiring the run to be NAMED ------
./apiscan verify  --evidence $E/evidence --run <run-id>
./apiscan report  --evidence $E/evidence --run <run-id> --out $E/reports \
                  --not-established $E/limits.txt --scope-note "..."
./apiscan redact  --evidence $E/evidence --run <run-id> \
                  --profile $E/profile.json --out $E/shareable
```

`plan` is the artifact to show a client before a live run: destination host and
port, transport, TLS posture, identities by name and purpose, request count and
every operation that may change data, by case id. It resolves no credential
value, so it can go in an approval e-mail.

`report`, `capture`, `reclassify`, `verify` and `redact` require `--run` or an
explicit `--latest`, and `--latest` only considers runs of the right *kind*.

### Where client data goes

| Artifact | Location |
|---|---|
| target profile, scope policy | engagement directory |
| credentials, certificates | engagement directory, `.env` / files, mode 0600 |
| evidence, findings, reports, PoC | engagement directory |
| **anything client-specific** | **engagement directory. Never here.** |

The framework writes nothing into its own tree at runtime. If you are about to,
that is the bug.

---

## 5. Describing a target

A profile has five parts that matter:

* **transport** -- base URL, optional proxy, TLS verification, client
  certificate mode. Use `client_cert.mode = "proxy"` when the target enforces
  mutual TLS *and* traffic goes through an intercepting proxy: the proxy
  terminates TLS and performs the upstream handshake, so the certificate must be
  configured inside the proxy, not passed to the HTTP client.
* **auth.identities** -- named credential sets, each with a `purpose`:
  `positive`, `wrong_role`, `invalid_credential`, `unauthenticated`. Generators
  ask for a purpose, not a name, so the corpus works regardless of naming.
* **endpoints** -- id, path, methods, which identifier namespace it owns, which
  payload template it uses.
* **payload_templates** -- a body plus the *declared meaning* of its fields:
  `identifier_path`, `correlation_path`, `status_flag_path`, `error_path`,
  `note_path`. Generators mutate by path, which is what makes them target-
  independent.
* **response_model** -- status-to-layer map, application envelope spec, edge
  block markers, business markers, verdict policy.

Four optional parts carry the honesty machinery:

* **transport.tls_verify.mode** -- `system` (the default: verify against the
  host trust store), `ca` (verify against `ca_path`, which **must exist** -- a
  missing file is a hard failure, never a silent downgrade), or `insecure`,
  which has to be written down deliberately and is then reported as a
  limitation of the whole run. An engagement behind an intercepting proxy
  should use `ca` with the CA fetched from the proxy's control endpoint: that
  verifies the proxy strictly instead of disabling verification.
* **transport.max_response_bytes** -- refuse to download more than this. The
  engagement mode applies its own ceiling too; the lower wins.
* **endpoints[].state_verification** -- how to READ BACK what a data-changing
  request did. Declaring it lets the framework confirm that a request which
  looked accepted actually changed something; omitting it makes the report say
  the resulting state was unverifiable, instead of saying nothing.
* **controlled_resources** -- objects whose owner is known, with the
  provenance of that claim, for object-level authorisation testing. With none
  declared, ownership cases are not generated and the report records
  object-level authorisation as not established. Incrementing identifiers
  until something answers proves nothing about authorisation and risks
  touching a real customer's record.
* **redaction** -- engagement-specific fields to remove when producing a
  redacted copy, on top of the credential headers, credential shapes and
  `${ENV:...}` values that are always removed.

Validate with `./apiscan validate`. The loader cross-checks references the
schema cannot express (unknown identifier spaces, undefined default identity,
duplicate endpoint ids).

---

## 6. Scope: how not to do damage

Scope matches on case **attributes**, not on a list of case ids:

* `state_mutating` -- defaults to **true** on every case. Forgetting to annotate
  denies rather than sends.
* `volume_class` -- `single` / `burst` / `sustained`
* `payload_class` -- `injection`, `oversize`, `malformed`, `auth`, ...
* `require_proxy` -- policy-level. When true, any case that would leave the
  intercepting proxy needs an authorisation for class `direct_transport`. Set
  it when the rules of engagement require a reviewable record of all traffic.
  Transport probes are direct by nature, so expect to authorise them
  explicitly.

`deny_classes` lists what is forbidden. To permit a class, add an
`authorisations` entry naming who approved it, when, and against what reference.
An authorisation may be endpoint-scoped and may expire.

### The default policy denies everything that can do damage

`DEFAULT_DENY` is `state_mutating`, `volumetric`, `destructive`,
`infrastructure_pivot`, `bulk_extraction`, `injection`, `oversize` and
`malformed`. **A default-scope run therefore sends nothing and is correctly
reported INCONCLUSIVE.**

The last three were previously permitted by default, on the reasoning that the
generators annotate them `state_mutating=False`. That reasoning was wrong in the
only case that matters. A payload designed to exercise a missing control reaches
the application precisely when the control is missing, and an injection that
succeeds, an oversize body that exhausts a buffer or a malformed document that
crashes a parser changes state or availability whatever the annotation says. A
case cannot truthfully declare itself harmless against a target whose handling
of it is the unknown under test.

So where this file once said that a default-scope run permits 265 of 352 cases
and withholds only the baselines, it now permits none of them. That is the gate
working, and the fix is an authorisation, never a wider policy.

`init-engagement` writes `list(DEFAULT_DENY)` rather than a hand-typed list, so
a scaffolded engagement can never start from a quietly weaker policy than the
framework's own default.

Never widen a scope policy to make a run proceed. Ask the operator.

An authorisation should be narrowed to what was actually approved: name the
`endpoints` (profile endpoint **ids**, not paths -- a path matches nothing and
the grant silently covers everything), set `expires_on`, and leave classes that
were not discussed denied. `authorised_by`, `authorised_on` and `reference` are
the audit record; a `reference` must resolve to something a third party can
retrieve.

### One gate, no exceptions

The gate used to live in `Runner.run_case`, which meant every other caller
reached the network around it: preflight's reachability and oracle probes, the
proxy forwarding and CA fetches, the fidelity comparison, the rate-limit burst
(whose `scope_policy` argument was accepted and then never consulted -- it read
as a gate at every call site while the only real check was a boolean the caller
set itself).

So the gate now lives in `Transport`, which **cannot be constructed without a
scope policy** and refuses to send anything it cannot attribute to a permitted
case or probe. `send(probe=...)` takes the case or a
`governance.scope.Probe`; a caller that supplies none gets one declared
`state_mutating` and `unclassified_request`, which the default policy denies.
An unlabelled request is an unreviewed request.

`Probe`, `ReadOnlyProbe` and `TransportProbe` give non-corpus requests a
case-shaped face. `ReadOnlyProbe` exists so that "this one is harmless" has to
be written down by a name a reviewer will read.

### Run limits are not scope

A scope policy decides whether a request is permitted; it says nothing about how
long a run may take, how much it may download, or what to do when the target
starts failing. `framework/governance/limits.py` holds those. A target answering
500 to everything is no longer being measured, so continuing is both useless as
evidence and the likeliest way an assessment causes the incident it was meant to
prevent.

## 6a. Evidence is client data, and it contains credentials

Run directories are created mode 0700 and every artifact mode 0600, and the
manifest's `access` block records whether the filesystem actually applied that
-- a platform that cannot must not leave a report implying it did.

This matters because of the trace files. `--trace-ascii` records the wire
exchange, which includes every request header, which includes the
`Authorization` or API-key value of every single request. A raw run directory
is therefore a credential store. **Never share one.**

```bash
./apiscan redact --evidence E --run <id> --profile P --pii --out shareable/
```

`evidence/redact.py` writes a parallel tree and never touches the original.
That is deliberate, and it is the review's own reasoning: redacting the only
original would undermine later verification. The copy carries a manifest
recording the SHA-256 of both the original and the copy, so a reader can
confirm which raw artifact a redacted one came from without being handed the
raw artifact.

What is always removed: the resolved values of the profile's `${ENV:...}`
references, the values of credential-bearing headers by name, and credential
shapes (JWTs, PEM private keys, AWS/GitHub/Slack tokens, Basic and Bearer
values). `--pii` adds e-mail addresses and long digit runs. Each distinct
secret gets a stable label (`[REDACTED:credential:1]`) so a reader can see
that two occurrences were the same value without learning it; labels are not
derived from the value, so they cannot confirm a guess.

Each run records `retention_days` (default 90) and a `retain_until` date.
`./apiscan purge` reports what is past retention and deletes only with
`--force`; a run with no recorded retention date is never deleted
automatically. A retention period nothing enforces is a sentence in a policy
document.

---

## 7. Honesty rules the code enforces

These exist because each one is a way an assessment quietly becomes untrue.

| Rule | Where |
|---|---|
| A request stopped before the application is `BLOCKED`, never a pass | `oracle/verdict.py` |
| A run with failing baselines is INCONCLUSIVE, not "all controls present" | `corpus/generators/retest.py`, `findings/coverage.py` |
| Blocked / skipped / errored are reported separately and excluded from pass rates | `findings/coverage.py` |
| The "what this did NOT establish" list is mandatory for an issuable report | `reporting/model.py` |
| Register aggregates are derived from run data, never hand-typed | `findings/register.py` |
| A register entry citing an unknown case id raises | `findings/register.py` |
| Evidence states how it was captured; a direct capture cannot claim a proxy | `evidence/provenance.py` |
| Remediation items are typed observable / not-externally-testable / risk-accepted | `corpus/generators/retest.py` |
| Every packet passes one gate: transport probes are scope-checked like cases | `governance/scope.py` (`TransportProbe`), `modules/tls_posture.py` |
| A derived artifact is hashed and recorded, so an offline command cannot break evidence verification | `evidence/store.py` (`register_derived`) |
| Nothing reaches the network without passing the gate: the transport cannot be built without a policy | `core/transport.py` (`Transport.__init__`, `_gate`) |
| TLS verification is on by default; a missing CA file is a hard failure, not a quiet downgrade | `core/transport.py` (`tls_args`) |
| Response headers are parsed from a different stream than the body, so a body cannot forge headers | `core/transport.py` (`send`), `evidence/store.py` (`render_response`) |
| A stored response is parsed by declared section length, so re-judging cannot be steered by content | `evidence/store.py` (`parse_response_text`) |
| A case id is validated before it becomes a filename | `core/pathguard.py` (`safe_component`), `corpus/case.py` |
| Raw evidence is mode 0600/0700 and the manifest states whether that was achieved | `evidence/store.py` (`restrict`, `finalise`) |
| A redacted copy never replaces the original, so the evidence manifest keeps verifying | `evidence/redact.py` (`redact_run`) |
| A mode's refusals cannot be lifted by an authorisation | `governance/scope.py` (`with_mode`), `governance/modes.py` |
| A run that stopped early reports `NOT-REACHED` and `INCOMPLETE`, never full coverage | `governance/limits.py`, `runner.py`, `findings/coverage.py` |
| A DEFECT requires reproduced-or-confirmed confidence; machine findings are `UNRESOLVED`/`suspected` | `findings/register.py` |
| A DEFECT with no expectation, observation, baseline, evidence or alternatives is not issuable | `findings/register.py` (`issuable_problems`), `reporting/model.py` |
| Target-controlled text cannot inject a spreadsheet formula into the deliverable | `reporting/renderers/safe.py` |
| `report` refuses to guess which run to use | `automation/cli/main.py` (`_resolve_run`) |

If you are tempted to relax one of these to make a report look better, that is
precisely the situation it was written for.

### Transport-layer evidence

TLS findings **cannot** be captured through an intercepting proxy. The proxy
terminates TLS and presents its own configured client certificate, so a "no
client certificate" test silently acquires one and the finding stops
reproducing. Capture those direct, and let the `CaptureMethod` travel with the
evidence into the filename, footer and report.

---

## 8. Adding a capability

* **A detector**: add a rule to `framework/oracle/rules/disclosure.json` with an
  id, severity, CWE and pattern. Add a positive fixture to
  `tests/unit/test_detectors.py` -- that suite asserts every rule has one.
* **A payload family**: add a generator to
  `framework/corpus/generators/families.py` and register it in `ALL_FAMILIES`.
  Derive a FRESH base per case (`_base(profile, endpoint)`); sharing one body
  reuses a correlation identifier and a target with idempotency protection will
  refuse everything after the first.
* **A phase**: add to `framework/methodology/phases.py` with an ordering weight
  that keeps mutation monotonic, then a generator in `generators/phases.py`.
* **A preflight check**: decorate a function with
  `@register(id, name, order, applies=...)` in `automation/preflight/checks.py`.
  Every failure must carry a concrete remedy string.
* **A report renderer**: consume `ReportModel`; do not reach into the register.

Every new unit needs a test. Run the suite with:

```bash
python3 -m unittest discover -s tests -t . -p "test_*.py"
```

Mark new work **EXTRACTED CAPABILITY** or **ENGINEERING IMPROVEMENT** in its
docstring. Do not present something newly written as previously proven.

---

## 9. Optional dependencies and degradation

The framework's core loop needs only the standard library plus `curl`.

| Dependency | Enables | Without it |
|---|---|---|
| `openpyxl` | xlsx workbook | Markdown + CSV; a note is printed |
| `Pillow` | PoC images embedded in the workbook | paths referenced instead; reported in `RenderResult.notes` |
| Chrome / Chromium | PNG PoC rendering | self-contained HTML artifact instead |
| `pyobjc-framework-Quartz` | proxy-window screenshots (macOS) | unavailable; use rendered evidence |
| `nmap` / `testssl.sh` | cipher enumeration | reported `NOT VERIFIED`, never silently skipped |

**Never report a capability as passing when its dependency is absent.** Return
`NOT VERIFIED` with the install command. `framework/core/errors.py` has
`DependencyUnavailable` for this.

`./apiscan version` states the build, the commit, the supported environments
and which of these capabilities THIS host actually has -- so a bug report can
distinguish an environment gap from a product defect, and a report can cite the
build that produced its evidence.

---

## 10. Changing the oracle

`tests/regression/test_oracle_differential.py` holds an independent reference
implementation of the original classification semantics and compares the two
across a generated matrix. Two divergences are documented and pinned:

1. a business-layer refusal satisfies an expectation of rejection under the
   `layered` policy (the source scored it as a missing control);
2. a 404 carrying the application's own envelope is attributed to the
   application rather than to a missing route.

If you change attribution or verdict mapping, that suite will fail. Decide
deliberately whether the change is an improvement, then update the pinned
divergence set and document it. Do not delete the test to make it pass.

---

## 11. Updates, validation and rollback

Git tracks history. Rollback of the *working tree* is by snapshot, which
is the mechanism to reach for mid-change, since it excludes evidence and
secrets by pattern and carries its own hash manifest:

```bash
./apiscan snapshot create --label before-change
./apiscan snapshot list
./apiscan snapshot rollback --id 20260101-120000-before-change
```

Snapshots live outside this tree, exclude evidence and secrets by pattern, and
carry a hash manifest. A rollback takes a safety snapshot of the current state
first, so a rollback is itself reversible.

An improvement proposed from an engagement must pass the gates in
`governance/improvement-policy.md` before integration: isolation, sanitisation,
static checks, the full test suite, and independent confidentiality validation.
**The validator is maintained separately from this framework and must never be
modified to make a change pass.** If verification cannot be completed, quarantine
the change and ask for human review.

---

## 12. Preventing contamination

Before any commit or share:

```bash
python3 -m unittest discover -s tests -t . -p "test_*.py"   # includes tests/security
```

`tests/security/test_hygiene.py` asserts: no credential-shaped literals, no
`.env`/key/certificate files, only RFC 2606 reserved hostnames and RFC 5737
documentation addresses, no target constants in modules, scope defaults to deny,
and no full-screen capture path.

That suite deliberately does **not** check for any specific client's
identifiers -- embedding such a list here would ship the very data this
framework exists to keep out. That check belongs to the operator's separate,
confidential validator.

If you are ever unsure whether something is client-specific: it is. Put it in
the engagement directory.
