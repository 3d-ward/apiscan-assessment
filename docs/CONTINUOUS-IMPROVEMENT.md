# Continuous improvement

A real engagement is where this framework's gaps become visible: a stack whose
errors no detector recognises, an authentication scheme with no provider, a
response shape the oracle mis-attributes. Those lessons are worth keeping. The
engagement they came from is not.

So an improvement travels back as **reconstructed generic capability**, never as
a copied artifact.

## What may and may not come back

| May | Must not |
|---|---|
| a new detector rule (pattern, severity, CWE) | the response that triggered it |
| a new payload family or phase generator | a payload containing client identifiers |
| a status-to-layer mapping for an API shape | the target's hostname or paths |
| an auth provider for a scheme | any credential, token or certificate |
| a preflight check | engagement-specific thresholds |
| a bug fix with a regression test | a fixture built from captured traffic |

If a lesson cannot be expressed without engagement data, it is not yet an
improvement -- it is still a finding. Generalise it first.

## Workflow

1. **Identify** the improvement during the engagement; note it, do not patch the
   framework in place from an engagement workspace.
2. **Isolate**: work in a copy of the framework, outside the engagement tree.
3. **Reconstruct** the change generically. Replace any captured value with a
   synthetic one (RFC 2606 domains, RFC 5737 addresses, `SYNTH-` identifiers).
4. **Test**: add unit coverage, and a regression test if it fixes a defect.
5. **Run the full suite**, including `tests/security`.
6. **Run independent confidentiality validation** with the operator's separate
   validator against the release candidate.
7. **Snapshot** the current framework: `./apiscan snapshot create --label pre-<change>`.
8. **Integrate** atomically only if every gate passed.
9. **Record** the change in `CHANGELOG.md`, marked EXTRACTED or IMPROVEMENT.
10. **Keep rollback available**: the snapshot from step 7 is the undo.

## Gates

An improvement is integrated only when **all** of these pass:

| Gate | Check |
|---|---|
| Isolation | reconstructed outside the engagement tree |
| Sanitisation | no client identifier, credential, hostname or captured artifact |
| Static | imports resolve; no literal target constants |
| Functional | full test suite green, including the new coverage |
| Security | `tests/security/test_hygiene.py` passes |
| Independent | the external validator reports PASS |
| Regression | no existing capability removed or silently weakened |

See `governance/improvement-policy.md` for the binding version.

## Rules for automated integration

Automatic integration is permitted **only** when every mandatory gate passes. It
must never:

* import a raw engagement artifact;
* overwrite the framework without a recoverable previous version;
* weaken a confidentiality control;
* bypass independent verification;
* introduce a hardcoded client dependency;
* silently remove an existing capability;
* synchronise an unverified change;
* **modify the validator to make a change pass.**

That last one is the important one. The validator is maintained separately from
this framework precisely so that the thing being checked cannot adjust the
check. An improvement that would require editing the validator is, by
definition, one that fails it.

If an improvement fails a gate, **quarantine** it: keep the reconstruction and
the failure reason, and request human review. Do not integrate partially.

## Versioning

`CHANGELOG.md` records, per change: what changed, whether it is an EXTRACTED
capability or an ENGINEERING IMPROVEMENT, which capability ids it touches, test
results, validation status, and the snapshot id to roll back to.
