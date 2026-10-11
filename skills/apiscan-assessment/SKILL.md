---
name: apiscan-assessment
description: Use when assessing an HTTP/JSON API against a named target; when asked to scan, probe, fuzz, re-validate or re-test API endpoints; when capturing proof-of-concept evidence for an API finding; or when building a findings register or report from captured API evidence. Also use when an apiscan entry point or a profile.json / scope-policy.json pair is present.
---

# apiscan-assessment

## Overview

apiscan-assessment generates a test corpus from a declarative target profile, executes
it behind a scope gate, and attributes each response to the layer of the stack
that answered it.

**An HTTP status code is not a verdict.** The same `400` may come from an edge
size limit, a media-type refusal or application validation, and many APIs
return `200` for everything and signal the real outcome in the body. The unit
of measurement is *whether a control exists and how deep it sits* — not
pass/fail.

**Nothing here authorises anything.** Authorisation, scope and target details
come from an engagement directory outside the framework. A profile naming a
host is not permission to send traffic to it. If you cannot point to a scope
policy with a recorded authorisation, ask — do not scan.

## Commands

Run from anywhere; paths point at the engagement directory.

| Command | Sends traffic |
|---|---|
| `init-engagement <dir>` | no |
| `validate --profile P [--scope S]` | no |
| `generate --profile P [--list]` | no |
| `preflight --profile P [--evidence E] [--offline] [--all]` | yes, a few probes |
| `scan --profile P --scope S --evidence E` | **yes** |
| `tls-posture --profile P --scope S --evidence E` | **yes, always direct** |
| `reclassify --profile P --evidence E` | no |
| `capture --evidence E --out O [--ids ...]` | no |
| `report --evidence E --out O --not-established FILE` | no |

`reclassify` needs no credentials — it re-judges stored bytes.

`--scope` is bracketed as optional on `scan`, where it falls back to the
default-deny policy. On `tls-posture` it is effectively required: the module
refuses outright without a policy, because it is the one that opens sockets to
the client's edge.

`report` defaults to the **latest** run. A `tls-posture` run is the latest run,
so pass `--run <corpus-run-id>` explicitly or the deliverable gets built from
two transport observations.

## Order of work

1. `validate`, then `generate --list`. Both send nothing; use them to confirm
   the target is actually described before anything goes out. **Check the
   profile is not still the scaffold** — `init-engagement` copies a synthetic
   profile that is schema-valid and fully runnable while pointing at
   `api.example.com`. `preflight` fails on this (`profile.placeholders`), but
   `validate` will happily pass it.
2. `preflight` before every `scan`. It catches the blockers that otherwise cost
   hours: proxy interception left ON (requests queue, history rows get empty
   response panes), a proxy that silently repairs payloads, and missing
   dependencies.
3. `scan`, narrowed with `--phases` / `--families` / `--endpoint` / `--ids`.
4. `reclassify` to re-judge without re-sending; `capture` for PoC images;
   `report` last.

## Things that are expensive to rediscover

**TLS evidence cannot go through the proxy.** The proxy terminates TLS and
presents its own configured client certificate, so a "no client certificate"
probe silently acquires one and the finding stops reproducing. Use
`tls-posture`, which is direct by construction and stamps `CaptureMethod.DIRECT`
into the filename, footer and report. Do **not** reach for `scan --direct` for
this: with `client_cert.mode = "proxy"` the HTTP client attaches no
certificate, so the whole corpus gets edge-blocked and the run tells you
nothing.

**Leave the proxy setup alone.** `tls-posture` never reads `transport.proxy`
and ignores `client_cert.mode`. The proxy can stay running and configured; you
do not need to edit the profile or dismantle anything.

**The finding is the contrast, not the rejection.** "Rejected with no
certificate" alone could mean the host is down. Pass all three:

```
tls-posture --profile P --scope S --evidence E --endpoint <id> \
  --client-cert CERT.pem --client-key KEY.pem \
  --untrusted-cert SELF.pem --untrusted-key SELF.key
```

No certificate vs. untrusted vs. issued. If the first two differ, the edge
validates the *issuing chain* rather than mere presence — a stronger result,
plus an Informational CWE-204 observation. The proxy holds the client
certificate but will not export it, so extract PEMs from the original `.p12`
into the engagement directory (`openssl pkcs12 -clcerts -nokeys` and
`-nocerts -nodes`), and generate the untrusted pair with
`openssl req -x509 -newkey rsa:2048 -nodes`.

**A default-scope run is correctly INCONCLUSIVE.** Most of the corpus still
goes out — `injection`, `oversize` and `malformed` are not denied by default —
but every baseline case is `state_mutating`, so the baselines do not run, and
losing them alone forces INCONCLUSIVE. That is the gate working. The fix is an
`authorisations` entry, never widening `deny_classes`.

Write the authorisation **narrowed to what was actually approved**:

```json
{"classes": ["state_mutating"],
 "endpoints": ["resource_create", "resource_update"],
 "authorised_by": "Name, Role, Client",
 "authorised_on": "2026-01-01",
 "reference": "email subject + Message-ID, archived at <engagement>/authorisations/...",
 "expires_on": "2026-01-31",
 "note": "Confirms the verbal approval of <date>. Volumetric remains denied."}
```

`endpoints` matches profile endpoint **ids**, not paths or URLs — a path there
silently matches nothing and the authorisation covers everything instead.
`expires_on` stops a grant outliving the engagement. `authorised_by`,
`authorised_on` and `reference` are `minLength: 1` because they *are* the audit
record: never invent them, and make `reference` resolve to something a third
party can retrieve. Ask the operator for the values.

**`require_proxy` gates direct transport.** When the rules of engagement
require a reviewable record of all traffic, set it; leaving the proxy then
needs a `direct_transport` authorisation. Transport probes are direct by
nature, so expect to authorise them explicitly.

**Client data never enters the framework tree.** Evidence, findings, reports
and credentials live in the engagement directory. The path guard refuses an
evidence root inside the tree, symlinks included. Credentials are `${ENV:NAME}`
references; a literal raises `SecretInProfileError`.

## Common mistakes

| Mistake | What actually happens |
|---|---|
| Reading a `403` as "the control works" | Attribute the layer first. A pre-application block is `BLOCKED`, never a pass. |
| `--no-baseline` to save time | Without baselines a negative result is indistinguishable from a broken harness. |
| Hand-typing a count into the register | Aggregates are derived from run data; a hand-typed one will contradict the coverage sheet. |
| Reporting a capability whose dependency is absent | Return `NOT VERIFIED` with the install command. |
| Issuing a report without `--not-established` | It will refuse. Every assessment has limits; state them. |
| Scanning the unedited scaffold | Schema-valid and runnable, but aimed at `api.example.com`. Real traffic to an uninvolved party, and a clean-looking report about nothing. |
| `report` straight after `tls-posture` | It takes the latest run. Pass `--run` for the corpus run. |

## Reading the output

`CONTROL-PRESENT` / `CONTROL-ABSENT` are case verdicts. The register's
*controls documented* count is distinct and usually much smaller — many cases
can evidence one control. Blocked, skipped and errored are reported separately
and excluded from pass rates.

In the repository, `CLAUDE.md` carries the full operating detail and
`docs/KNOWN-LIMITATIONS.md` states what the framework does not do.
