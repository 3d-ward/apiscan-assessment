# Usage

## 1. Scaffold an engagement

```bash
./apiscan init-engagement ~/engagements/acme-2026 --name acme-api --reference ENG-2026-14
```

Creates, OUTSIDE the framework tree:

```
~/engagements/acme-2026/
  profile.json        target description (placeholders -- replace them)
  scope-policy.json   rules of engagement (default-deny)
  .env                credentials, mode 0600, gitignored
  evidence/ findings/ reports/ poc/
```

## 2. Describe the target

Edit `profile.json`. The parts that carry meaning:

```jsonc
"endpoints": [
  {"id": "order_create", "path": "/v2/orders", "methods": ["POST"],
   "identifier_space": "order_ref", "payload_template": "standard"}
],
"identifier_spaces": {
  "order_ref":   {"generator": "pattern:ORD-########"},
  "correlation": {"generator": "hex:64"}
},
"payload_templates": {
  "standard": {
    "body": {"order": {"ref": "SEED", "note": null}, "ok": true, "traceId": "SEED"},
    "identifier_path": "order.ref",      // the resource identifier
    "correlation_path": "traceId",       // the per-request correlation id
    "status_flag_path": "ok",            // a boolean outcome flag
    "error_path": "order.error",
    "note_path": "order.note"
  }
}
```

Generators mutate by these declared paths, so the same corpus works against any
API once the paths are named. Omitting an optional path simply skips the
families that depend on it.

The `response_model` tells the oracle how to read an answer:

```jsonc
"response_model": {
  "status_layers": {"409": "business_reject", "422": "validation_reject"},
  "envelope": {"code_path": "status.code", "remark_path": "status.message",
               "success_values": ["OK"], "auth_failure_values": ["AUTH_FAILED"]},
  "edge_block_markers": ["No required SSL certificate was sent"],
  "business_markers": ["not found", "already processed"]
}
```

## 3. Credentials

Never in the profile. Reference them:

```jsonc
"headers": {"x-api-key": "${ENV:ACME_PRIMARY_KEY}"}
```

and put the values in `.env`, then `set -a; . ./.env; set +a`. The loader raises
`SecretInProfileError` on a literal.

Define at least a `positive` identity. Add `wrong_role` and
`invalid_credential` identities to unlock phases P1 and P2.

## 4. Scope

```jsonc
{
  "schema": "scope-policy/1",
  "deny_classes": ["volumetric", "destructive", "infrastructure_pivot",
                   "bulk_extraction"],
  "max_risk": "mutating",
  "authorisations": [{
    "classes": ["state_mutating"],
    "authorised_by": "Acme Security Lead",
    "authorised_on": "2026-10-01",
    "reference": "RoE-2026-14 s.4",
    "expires_on": "2026-12-31"
  }]
}
```

Baseline calibration cases mutate state. Without a `state_mutating`
authorisation they are denied, the oracle is uncalibrated, and the run is
correctly reported INCONCLUSIVE.

> `docs/WORKFLOW.md` is the authoritative workflow. This document is the
> longer-form walkthrough; where the two disagree, that one is right.

## 5. Offline review first

```bash
./apiscan validate --profile .../profile.json --scope .../scope-policy.json
./apiscan generate --profile .../profile.json --scope .../scope-policy.json --list
./apiscan plan     --profile .../profile.json --scope .../scope-policy.json \
                   --out .../plan.json
```

None of these sends anything. Read the case list before you send it, and send
the **plan** to whoever is authorising the work: it states the destination host
and port, the transport, the TLS posture, the identities by name and purpose,
the per-endpoint case counts, the number of requests that will go out, and every
operation that may change data, by case id. It resolves no credential value, so
it is safe to paste into an e-mail.

## 6. Preflight

```bash
./apiscan preflight --profile .../profile.json --scope .../scope-policy.json \
                    --evidence .../evidence --all
```

**Preflight sends traffic.** It issues an empty-body POST to the first
endpoint, a well-formed baseline body, and -- when a proxy is configured and
`fidelity_expectations.enabled` is set -- a 200 KB body, a NUL byte and a
truncated JSON document. Each is a declared probe judged by the scope policy
before it leaves, which is why `--scope` is required unless you pass
`--offline`. A probe the policy does not authorise is reported `NOT VERIFIED`
and is not sent; `NOT VERIFIED` is not a pass.

Checks run in order so the first failure is the thing to fix, and every failure
carries a remedy. When a proxy is configured and
`fidelity_expectations.enabled` is set, it also verifies that the proxy does not
alter the edge cases the corpus depends on -- if it does, the affected payload
classes are flagged as not dependable rather than quietly producing wrong
results.

## 7. Scan

```bash
./apiscan scan --profile .../profile.json --scope .../scope-policy.json \
               --evidence .../evidence --mode limited-live --phases P1,P2 \
               --note "phase 1, authorised under RoE s.4"
```

`scan` prints the test plan and then asks you to confirm it before opening a
socket. `--yes` skips the prompt; a non-interactive caller proceeds but the plan
is still printed and recorded with the evidence.

`--mode` defaults to `limited-live`, which runs only an explicitly named subset
(`--ids` / `--families` / `--phases` / `--endpoint`) under hard ceilings, and
refuses volumetric, destructive, oversize and injection classes outright
whatever the policy authorises. Use `--mode active` when the engagement has
agreed to those:

```bash
./apiscan scan ... --mode limited-live --phases P1,P2   # cautious, explicit
./apiscan scan ... --mode active --up-to P3             # stop before P4+
./apiscan scan ... --mode active --families C,D,E       # payload families only
```

Tighten the ceilings further with `--max-cases`, `--max-duration-s`,
`--max-response-bytes`, `--delay-s` and `--stop-after-server-errors`. They only
ever tighten: asking for more than the mode allows is clamped.

If the run stops on a ceiling or a stop condition -- three consecutive server
errors, say -- the cases it never sent are recorded `NOT-REACHED`, coverage
reports `INCOMPLETE`, and the report lists them as not established. A target
answering 500 to everything is no longer being measured.

Each run writes a timestamped evidence directory with per-case request bytes,
full response, wire trace, a results file and a SHA-256 manifest. The directory
is mode 0700 and the artifacts 0600, and it records a retention date.

## 8. Re-judge without re-sending

```bash
./apiscan reclassify --profile .../profile.json --evidence .../evidence \
                     --run <run-id>
```

Re-runs the oracle over stored responses. Use after changing classification
rules: no extra traffic, no repeated state mutation.

## 9. Report

```bash
cat > .../limits.txt <<'EOF'
Credential lifetime, rotation and revocation are policy properties and were not
observable from the client side.
Rate limiting was not exercised; volumetric cases are out of scope.
The GraphQL endpoint was not in scope and was not tested.
EOF

./apiscan report --evidence .../evidence --run <run-id> --out .../reports \
                 --not-established .../limits.txt \
                 --scope-note "..." --engagement "ENG-2026-14" --promote
```

**Name the run.** `report`, `capture`, `reclassify`, `verify` and `redact`
require `--run <run-id>` or an explicit `--latest`, and `--latest` only
considers runs of the right *kind*. A `tls-posture` run is two transport
observations and is very often the last thing done before writing up;
defaulting to "whatever ran last" is how a deliverable gets built from it.

Limits the run recorded about itself -- unverifiable state changes, untested
object-level authorisation, an early stop, an unverified TLS path -- are merged
into the "not established" list automatically. Those are the ones most easily
forgotten days later, and the ones a reader most needs.

`--not-established` is required for an issuable report. Without it the renderer
emits the report with a banner saying it is not issuable and lists why.

Add authored findings with `--register findings.json`:

```json
[{"id": "D-01", "title": "...", "severity": "High", "cwe": "CWE-639",
  "kind": "DEFECT", "confidence": "reproduced",
  "expected_behaviour": "The service rejects an identifier from another namespace.",
  "observed_behaviour": "It accepted it and answered 200 with the record created.",
  "alternative_explanations": [
    "the namespaces may be interchangeable by design -- confirmed not to be with the client"],
  "impact": "...", "recommendation": "...",
  "case_ids": ["A01", "A03", "P3-02"]}]
```

A `DEFECT` requires `confidence` of `reproduced` or `manually-confirmed` -- the
register refuses to construct one at `suspected`, because an automated verdict
is not a reproduced defect. `--promote` turns machine findings into
`UNRESOLVED` rows at `suspected` confidence, with the alternative explanations
a reviewer has to rule out. Raising one to `DEFECT` means reproducing it.

A report is not issuable while any `DEFECT` row lacks an expectation, an
observation, a working baseline, evidence, a recommendation or its alternative
explanations. Those are the elements a client needs in order to disagree with a
finding, which is exactly when a report has to hold up.

Affected endpoints, occurrence counts and evidence paths are derived from the
run. A cited case id that is not in the run data raises, so a stale definition
fails loudly rather than producing a finding with nothing behind it.

## 10. PoC evidence

```bash
./apiscan capture --evidence .../evidence --run <run-id> --out .../poc \
                  --ids A01,C02
```

Renders the verbatim stored bytes to HTML and PNG. It touches no screen-capture
API, so nothing else on your desktop can appear in a deliverable, and it is safe
to run unattended. Evidence is stamped `derived`; a report cannot claim it came
through a proxy.

## 11. Before anything leaves the engagement

```bash
./apiscan verify --evidence .../evidence --run <run-id>
./apiscan redact --evidence .../evidence --run <run-id> \
                 --profile .../profile.json --pii --out .../shareable
```

`verify` re-hashes the run against its manifest. `redact` writes a redacted
**copy**; the raw originals are never modified, so the manifest keeps verifying
and a third party can still be given the original later if a finding is
disputed.

Redact because of the trace files. `--trace-ascii` records the wire exchange,
which includes every request header, which includes the `Authorization` or
API-key value of every single request. **A raw run directory is a credential
store. Do not share one.**

Redaction is pattern-based, so **read the copy before you send it** -- a secret
the target invented and returned in an unrecognised shape can survive it.
Declare your client's identifier formats in the profile's `redaction.patterns`.

## 12. When the engagement is over

```bash
./apiscan purge --evidence .../evidence              # reports; deletes nothing
./apiscan purge --evidence .../evidence --force      # deletes expired runs
```

Each run records a retention date (`--retention-days` on `scan`, default 90).
`purge` reports what is past it and deletes only with `--force`. Check first
that every finding citing those runs has been delivered and accepted: this
removes the evidence behind them.

## Reading verdicts

| Verdict | Meaning |
|---|---|
| `CONTROL-PRESENT` | the declared expectation was met |
| `CONTROL-ABSENT` | it was not -- a control is missing |
| `OVER-BLOCKED` | a legitimate request was refused; negative results are now suspect |
| `BLOCKED` | stopped before the application; **not** a pass and **not** a failure |
| `ERROR` | the target errored or did not respond |
| `OBSERVED` | no pass/fail declared; judged by detectors or by hand |
| `UNCLEAR` | the outcome does not map to a verdict; needs review |

`control_depth` says whether the refusal happened before business logic or
inside it. A business-layer refusal is still a control, but a validation finding
should set `shallow_reject_required` to demand a pre-business one.
