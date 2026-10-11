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
./apiscan preflight --profile ./profile.json --evidence ./evidence --all
```
Record the preflight output. Do not proceed past a blocker.

## Execution order
```
./apiscan scan --phases P1,P2 ...      # authz/authn, non-mutating
./apiscan scan --up-to P3 ...          # stop before business-logic abuse
./apiscan scan --families C,D,E ...    # payload families
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
