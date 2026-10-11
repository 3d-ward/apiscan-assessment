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

## 5. Dry run first

```bash
./apiscan validate --profile .../profile.json --scope .../scope-policy.json
./apiscan generate --profile .../profile.json --scope .../scope-policy.json --list
```

Neither sends anything. Read the case list before you send it.

## 6. Preflight

```bash
./apiscan preflight --profile .../profile.json --evidence .../evidence --all
```

Checks run in order so the first failure is the thing to fix, and every failure
carries a remedy. When a proxy is configured and
`fidelity_expectations.enabled` is set, it also verifies that the proxy does not
alter the edge cases the corpus depends on -- if it does, the affected payload
classes are flagged as not dependable rather than quietly producing wrong
results.

## 7. Scan

```bash
./apiscan scan --profile .../profile.json --scope .../scope-policy.json \
               --evidence .../evidence --note "phase 1, authorised under RoE s.4"
```

Run phases incrementally when the target is sensitive:

```bash
./apiscan scan ... --phases P1,P2            # non-mutating first
./apiscan scan ... --up-to P3                # stop before business-logic abuse
./apiscan scan ... --families C,D,E          # payload families only
```

Each run writes a timestamped evidence directory with per-case request bytes,
full response, wire trace, a results file and a SHA-256 manifest.

## 8. Re-judge without re-sending

```bash
./apiscan reclassify --profile .../profile.json --evidence .../evidence
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

./apiscan report --evidence .../evidence --out .../reports \
                 --not-established .../limits.txt \
                 --scope-note "..." --engagement "ENG-2026-14" --promote
```

`--not-established` is required for an issuable report. Without it the renderer
emits the report with a banner saying it is not issuable and lists why.

Add authored findings with `--register findings.json`:

```json
[{"id": "D-01", "title": "...", "severity": "High", "cwe": "CWE-639",
  "description": "...", "impact": "...", "recommendation": "...",
  "case_ids": ["A01", "A03", "P3-02"]}]
```

Affected endpoints, occurrence counts and evidence paths are derived from the
run. A cited case id that is not in the run data raises, so a stale definition
fails loudly rather than producing a finding with nothing behind it.

## 10. PoC evidence

```bash
./apiscan capture --evidence .../evidence --out .../poc --ids A01,C02
```

Renders the verbatim stored bytes to HTML and PNG. It touches no screen-capture
API, so nothing else on your desktop can appear in a deliverable, and it is safe
to run unattended. Evidence is stamped `derived`; a report cannot claim it came
through a proxy.

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
