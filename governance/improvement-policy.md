# Improvement intake policy

Binding rules for changing this framework. `docs/CONTINUOUS-IMPROVEMENT.md`
explains the intent; this file is the checklist.

## G1 Isolation
The change is reconstructed in a workspace outside any engagement directory.
No file is copied from an engagement. **Blocking.**

## G2 Sanitisation
The change contains no client identifier, hostname, address, credential,
certificate, captured request or response, or engagement reference. Every
example value is synthetic: RFC 2606 reserved domains, RFC 5737 documentation
addresses, `SYNTH-` identifiers. **Blocking.**

## G3 Static integrity
All imports resolve. No module-level target constant. No new third-party
runtime dependency in the core loop. **Blocking.**

## G4 Functional
`python3 -m unittest discover -s tests -t . -p "test_*.py"` passes in full. New
behaviour has unit coverage; a defect fix has a regression test that fails
before the fix. **Blocking.**

## G5 Security hygiene
`tests/security/test_hygiene.py` passes. **Blocking.**

## G6 Independent confidentiality validation
The operator's separate validator reports PASS against the release candidate.
The validator is maintained outside this framework and **must not be modified to
make a change pass**. A change that requires editing the validator fails by
definition. **Blocking.**

## G7 No silent regression
No capability is removed or weakened without an explicit, recorded decision. The
capability registry is updated when a capability's status changes.
**Blocking.**

## G8 Provenance
Each changed unit is marked EXTRACTED CAPABILITY or ENGINEERING IMPROVEMENT.
Newly written functionality is never presented as previously proven.
**Blocking.**

## G9 Rollback
A snapshot of the pre-change framework exists and its id is recorded in the
changelog entry. **Blocking.**

## G10 Documentation
`CHANGELOG.md` is updated. If the change alters behaviour an operator relies on,
the relevant document under `docs/` is updated too. **Non-blocking but
required before release.**

---

## Outcomes

| Outcome | Meaning |
|---|---|
| PASS | every blocking gate passed; integrate atomically |
| FAIL | a blocking gate failed; do not integrate |
| BLOCKED | a gate could not be run; do not integrate |
| NOT VERIFIED | a gate was skipped (e.g. a missing dependency); record explicitly and do not convert to PASS |

An unknown result is never recorded as a pass.

## Quarantine

A change that fails or cannot be verified is quarantined: the reconstruction and
the failure reason are kept together, outside the framework, pending human
review. Partial integration is not permitted -- a half-applied change leaves the
framework in a state no snapshot describes.
