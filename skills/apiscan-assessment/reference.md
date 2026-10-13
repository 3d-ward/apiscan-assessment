# apiscan-assessment — reference

Loaded from `SKILL.md` when you are actually running something. `SKILL.md`
carries what the code cannot refuse you for; this file carries the procedures.
`docs/WORKFLOW.md` in the repository remains authoritative where they differ.

## Starting an engagement

```bash
./apiscan init-engagement ~/engagements/acme-2026   # outside the framework tree
cd ~/engagements/acme-2026
# edit profile.json      -- describe the target, no secrets
# edit scope-policy.json -- rules of engagement, default-deny
# fill .env              -- credentials, mode 0600
set -a; . ./.env; set +a
```

With `E=~/engagements/acme-2026`, offline first — none of these send:

```bash
./apiscan validate --profile $E/profile.json --scope $E/scope-policy.json
./apiscan generate --profile $E/profile.json --scope $E/scope-policy.json --list
./apiscan plan     --profile $E/profile.json --scope $E/scope-policy.json \
                   --out $E/plan.json
```

Then readiness, which does send gated probes unless `--offline`:

```bash
./apiscan preflight --profile $E/profile.json --scope $E/scope-policy.json \
                    --evidence $E/evidence
```

Then the live run, which prints the plan and asks before opening a socket:

```bash
./apiscan scan --profile $E/profile.json --scope $E/scope-policy.json \
               --evidence $E/evidence \
               --mode limited-live --endpoint <id> --families B
```

Afterwards, all offline, all requiring the run to be named:

```bash
./apiscan verify  --evidence $E/evidence --run <run-id>
./apiscan report  --evidence $E/evidence --run <run-id> --out $E/reports \
                  --not-established $E/limits.txt --scope-note "..."
./apiscan redact  --evidence $E/evidence --run <run-id> \
                  --profile $E/profile.json --pii --out $E/shareable
```

**Check the profile is not still the scaffold.** `init-engagement` writes a
synthetic profile that is schema-valid and fully runnable while pointing at
`api.example.com`. `validate` passes it happily; `preflight` catches it with
the `profile.placeholders` check. A scan of the unedited scaffold produces a
complete, meaningless run.

`--lax-env` lets the offline commands run before the credentials are populated.
It does not apply to anything that sends.

## Authorisations

A denied class is answered by an entry narrowed to what was actually approved:

```json
{"classes": ["state_mutating"],
 "endpoints": ["resource_create", "resource_update"],
 "authorised_by": "Name, Role, Client",
 "authorised_on": "2026-01-01",
 "reference": "email subject + Message-ID, archived at <engagement>/authorisations/...",
 "expires_on": "2026-01-31",
 "note": "Confirms the verbal approval of <date>. Volumetric remains denied."}
```

`endpoints` matches profile endpoint **ids**, not paths. A path there matches
nothing, and because an empty endpoint set means "any endpoint", the entry then
silently covers the whole target instead of the two you named. This is the one
mistake in this file that neither the schema nor the loader will catch.

`reference` must resolve to something a third party can retrieve. It is checked
for non-emptiness only, which is exactly why inventing one is undetectable
later.

## Transport probes and `require_proxy`

A `TransportProbe` declares `use_proxy=False` by construction, carries the
class `transport_probe`, and is not state-mutating. Consequences, verified
against `framework/governance/scope.py` and `framework/governance/modes.py`:

* `transport_probe` and `direct_transport` are in no default deny list and in
  no mode's hard denies, so with a scaffolded policy `tls-posture` is permitted
  with no authorisation at all.
* `require_proxy` is unset in a scaffolded policy. The direct-transport check
  in `ScopePolicy.evaluate` only runs when it is true.
* Set `require_proxy: true` and add `transport_probe` and `direct_transport`
  to `deny_classes` when the rules of engagement require a reviewable record of
  every packet. Only then does an authorisation for a transport probe gate
  anything.

Under `offline-review` nothing is sent regardless, but that protection comes
from the mode's `sends_traffic=False`, not from the class gate.

## Transport-layer evidence

TLS findings cannot be captured through an intercepting proxy: the proxy
terminates TLS and presents its own configured client certificate, so a "no
client certificate" test silently acquires one and the finding stops
reproducing. `tls-posture` is direct by construction, never reads
`transport.proxy` and ignores `client_cert.mode`, so the proxy can stay running
and configured. Do not substitute `scan --direct`: with
`client_cert.mode = "proxy"` the HTTP client attaches no certificate, every
case is edge-blocked, and the run establishes nothing.

**The finding is the contrast, not the rejection.** "Rejected with no
certificate" alone is consistent with the host simply being down. Pass all
three:

```bash
./apiscan tls-posture --profile $E/profile.json --scope $E/scope-policy.json \
  --evidence $E/evidence --endpoint <id> \
  --client-cert CERT.pem     --client-key KEY.pem \
  --untrusted-cert SELF.pem  --untrusted-key SELF.key
```

No certificate versus untrusted versus issued. If the first two differ, the
edge validates the issuing chain rather than mere presence — a stronger result,
plus an Informational CWE-204 observation. Server-certificate verification is
deliberately off for these three probes, because verifying it would abort the
handshake before the client-certificate question is reached.

## Evidence, redaction and retention

Run directories are mode 0700 and artifacts 0600, and the manifest's `access`
block records whether the filesystem actually applied that — on Windows it
cannot, and the manifest says so rather than implying otherwise.

`--trace-ascii` records the wire exchange, so every request's credential is in
the trace files. Before anything leaves the engagement:

```bash
./apiscan redact --evidence $E/evidence --run <id> \
                 --profile $E/profile.json --pii --out $E/shareable
```

Always removed: the resolved values of the profile's `${ENV:...}` references,
the values of credential-bearing headers by name, and credential shapes (JWTs,
PEM private keys, AWS/GitHub/Slack tokens, Basic and Bearer values). `--pii`
adds e-mail addresses and long digit runs. Each distinct secret gets a stable
label such as `[REDACTED:credential:1]`, so a reader can see two occurrences
were the same value without learning it; labels are not derived from the value,
so they cannot confirm a guess.

The originals are never modified — the evidence manifest has to keep verifying,
and redacting the only copy would destroy what a third party checks a finding
against. The copy's manifest records the SHA-256 of both original and copy.

Two boundaries worth stating to whoever receives it: redaction is
pattern-based, so a secret the target invented in an unrecognised shape can
survive it — read a redacted copy before sending it. And literal credential
matching needs the environment still populated; after an engagement clears its
secrets, only the shape and header passes apply.

Each run records `retention_days` (default 90) and a `retain_until` date.
`./apiscan purge` reports what is past retention and deletes only with
`--force`. A run with no recorded retention date is never deleted
automatically.

## Naming the run

`report`, `capture`, `reclassify`, `verify` and `redact` require `--run <id>`
or an explicit `--latest`, and `--latest` only considers runs of the right
kind. A `tls-posture` run is two transport observations and is often the last
thing done before writing up, so defaulting to "whatever ran last" is how a
deliverable gets built from it.

`reclassify` re-judges stored bytes and needs no credentials resolved. A stored
response is parsed by declared section length, so re-judging cannot be steered
by response content.

## Reading the output

`CONTROL-PRESENT` and `CONTROL-ABSENT` are case verdicts. The register's
*controls documented* count is a different number and usually much smaller —
many cases can evidence one control. `BLOCKED`, `SKIPPED`, `NOT-REACHED` and
errored cases are reported separately and excluded from pass rates.

`BLOCKED` means a pre-application control answered, so the case never reached
what it was meant to test. `NOT-REACHED` means a stopped run never sent it,
which is distinct from `SKIPPED` ("the engagement excluded this") and makes
coverage report `INCOMPLETE`. Failing baselines make the whole run
`INCONCLUSIVE` — without a working baseline a negative result is
indistinguishable from a broken harness, which is why `--no-baseline` is a
false economy.

`UNCLEAR` on a 404 with no business signal means the route may not exist;
verify the endpoint path before drawing any conclusion.

A verdict carries `control_depth` under the default `layered` policy: a
business-layer refusal is the control existing but sitting deeper than a
validation boundary. Use `validation_strict`, or a case's
`shallow_reject_required`, when a pre-business refusal is what the finding is
about.

## State and ownership

`endpoints[].state_verification` declares how to read back what a
data-changing request did. Declared, the framework confirms that a request
which looked accepted actually changed something; omitted, the report states
the resulting state was unverifiable rather than saying nothing.

`controlled_resources` declares objects whose owner is known, with the
provenance of that claim. With none declared, ownership cases are not generated
and the report records object-level authorisation as not established — which is
the honest outcome, and better than incrementing identifiers against a live
system.

## Degradation

Optional dependencies degrade to `NOT VERIFIED`, never to a pass: `openpyxl`
for the workbook, `Pillow` for embedded PoC images, Chrome for PNG rendering,
`pyobjc-framework-Quartz` for proxy-window capture, `nmap`/`testssl.sh` for
cipher enumeration. `./apiscan version` states which of them this host has and
what each absence costs; `docs/KNOWN-LIMITATIONS.md` states what the framework
does not do at all.
