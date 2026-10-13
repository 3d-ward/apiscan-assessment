# <ENGAGEMENT> runbook

Generated from the target profile. Keep it in the engagement directory.

## Authorisation
Scope reference: <RoE DOC s.N>  |  Authorised by: <NAME>  |  Window: <DATES>
State-mutating testing authorised: <YES/NO, reference>
Volumetric testing authorised: <YES/NO, reference>

Explicit exclusions: <...>

## Target
Base URL / endpoints / identities / proxy / client certificate location.

## Preparation
```
set -a; . ./.env; set +a
./apiscan validate  --profile ./profile.json --scope ./scope-policy.json
./apiscan plan      --profile ./profile.json --scope ./scope-policy.json
./apiscan preflight --profile ./profile.json --scope ./scope-policy.json \
                    --evidence ./evidence --all   # SENDS gated probes
```
Record the preflight output. Do not proceed past a blocker.

## Execution order
```
./apiscan scan --mode limited-live --phases P1,P2 ...   # cautious, explicit
./apiscan scan --mode active --up-to P3 ...            # stop before P4+
./apiscan scan --mode active --families C,D,E ...      # payload families

# Before anything leaves the engagement:
./apiscan verify --evidence ./evidence --run <run-id>
./apiscan redact --evidence ./evidence --run <run-id> \
                 --profile ./profile.json --out ./shareable
```
After each stage: confirm baselines passed. A failed baseline means stop and
explain before continuing.

## Evidence
Run directories under `./evidence/`. Verify integrity before reporting:
`EvidenceStore.verify(<run dir>)`.

## Contacts
Client technical contact / escalation / out-of-hours.

## Stop conditions
- a baseline fails and cannot be explained
- an unexpected production impact is observed or reported
- any case reaches a system outside the authorised scope
- the authorisation window closes
