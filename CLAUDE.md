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
  oracle/        layer attribution, verdict mapping, envelope decoding,
                 detector rules (data, in oracle/rules/*.json)
  evidence/      evidence store with SHA-256 manifest, capture provenance
  governance/    scope policy (attribute-matched), authorisation records
  findings/      register (DEFECT/UNRESOLVED/CONTROL), coverage accounting
  reporting/     report model + markdown / csv / xlsx renderers
  modules/       rate_limit, tls_posture, response_headers
  runner.py      scope gate -> transport -> evidence -> oracle -> record

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

```
./apiscan init-engagement <dir>   scaffold an engagement OUTSIDE this tree
./apiscan validate      --profile P [--scope S]    sends nothing
./apiscan generate      --profile P [--list]       sends nothing
./apiscan preflight     --profile P [--offline] [--json]
./apiscan scan          --profile P --evidence E [--scope S] [--direct]
./apiscan reclassify    --profile P --evidence E   sends nothing
./apiscan tls-posture   --profile P --evidence E [--scope S] [--ciphers]
./apiscan report        --evidence E --out O --not-established FILE
./apiscan capture       --evidence E --out O       sends nothing
./apiscan snapshot      create | list | rollback --id ID
```

`validate`, `generate`, `reclassify` and `capture` never emit a request. Use
them freely -- `reclassify` does not even need the credentials resolved, since
it re-judges stored bytes.

Two commands send traffic, and both pass the scope gate: `scan`, and
`tls-posture`. The latter is **always DIRECT** -- an intercepting proxy
terminates TLS and presents its own client certificate, so transport evidence
captured through one does not reproduce. Set `require_proxy` in the scope
policy and transport probes will need an explicit `direct_transport`
authorisation, which is the intended friction.

---

## 4. Starting a new engagement

```bash
./apiscan init-engagement ~/engagements/acme-2026   # outside this tree
cd ~/engagements/acme-2026
# 1. edit profile.json      -- describe the target (no secrets)
# 2. edit scope-policy.json -- rules of engagement (default-deny)
# 3. fill .env              -- credentials, mode 0600
set -a; . ./.env; set +a
```

Then, in order:

```bash
./apiscan validate  --profile ~/engagements/acme-2026/profile.json \
                    --scope   ~/engagements/acme-2026/scope-policy.json
./apiscan preflight --profile ~/engagements/acme-2026/profile.json \
                    --evidence ~/engagements/acme-2026/evidence
./apiscan generate  --profile ~/engagements/acme-2026/profile.json --list
./apiscan scan      --profile ~/engagements/acme-2026/profile.json \
                    --scope ~/engagements/acme-2026/scope-policy.json \
                    --evidence ~/engagements/acme-2026/evidence
```

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

The default policy denies `state_mutating`, `volumetric`, `destructive`,
`infrastructure_pivot` and `bulk_extraction`. **A default-scope run therefore
executes no baseline cases and is correctly reported INCONCLUSIVE** -- baselines
mutate state. That is not a bug; it is the gate working.

Read that precisely: the default gate does *not* stop the run. Against the
example profile it permits 265 of 352 cases and denies 87, because `injection`,
`oversize` and `malformed` are not in `DEFAULT_DENY`. What it withholds is the
four baselines, and losing those alone is enough to force INCONCLUSIVE --
without a baseline, a rejection cannot be told apart from a broken harness or a
target that refuses everything.

Never widen a scope policy to make a run proceed. Ask the operator.

An authorisation should be narrowed to what was actually approved: name the
`endpoints` (profile endpoint **ids**, not paths -- a path matches nothing and
the grant silently covers everything), set `expires_on`, and leave classes that
were not discussed denied. `authorised_by`, `authorised_on` and `reference` are
the audit record; a `reference` must resolve to something a third party can
retrieve.

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
