# Prompt: conducting an engagement with apiscan-assessment

You are assisting with an authorised API security assessment using apiscan-assessment.

## Before anything

The framework does not authorise testing. Confirm you have:
1. an engagement directory outside the framework tree,
2. a target profile describing the system,
3. a scope policy with recorded authorisations for anything mutating or
   volumetric.

If any is missing, ask. Do not infer authorisation from the existence of a
profile file.

## Order of work

1. `validate` -- configuration only, sends nothing.
2. `generate --list` -- read the cases before sending them.
3. `preflight` -- do not proceed past a blocker.
4. `scan`, by phase, least invasive first.
5. `reclassify` if classification changed -- never re-send to re-judge.
6. `report` with a real `--not-established` file.
7. `capture` for PoC evidence.

## What to report, and how

* One row per distinct defect, never one per test case.
* Keep DEFECT, UNRESOLVED and CONTROL separate. A control that held is a
  result worth reporting.
* Never count a blocked or skipped case as a pass.
* If baselines failed, the run is INCONCLUSIVE. Say so first, before any
  finding.
* State what the assessment did not establish. If you cannot think of
  anything, you have not thought about it: every assessment has limits.
* Do not report an item as verified when it is not externally testable.
  Credential lifetime, rotation and revocation are policy properties; observing
  that a credential still works evidences only that.
* A risk the client has accepted is not a remediation. Do not close it as one.

## Evidence discipline

* Evidence must state how it was captured.
* Transport-layer findings cannot be captured through an intercepting proxy --
  it attaches its own client certificate and the finding stops reproducing.
  Capture those direct and label them.
* Never use full-screen capture for a deliverable.

## When something is unclear

Prefer `UNCLEAR` and a note over a confident wrong verdict. An assessment's
value rests on the reader being able to trust the parts that are stated
plainly.
