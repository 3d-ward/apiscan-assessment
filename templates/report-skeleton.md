# <ENGAGEMENT> -- API security assessment

Target: <TARGET>  |  Assessed: <DATES>  |  Report date: <DATE>
Run id: <RUN-ID>  |  Status: <COMPLETE | QUALIFIED | INCONCLUSIVE>

## How the verdict was decided
<!-- REQUIRED. State the basis before the results, so a reader can judge them.
     Cover: expectations declared before execution; attribution to the layer
     that answered; that HTTP status alone is not a verdict; that a request
     stopped before the application is BLOCKED and never a pass; and that no
     verdict is taken from any status the client supplied. -->

## Result
<!-- REQUIRED. Confirmed defects, unresolved items, controls verified, and the
     execution tally: planned / executed / skipped / blocked / errored /
     conclusive. Severity counts cover CONFIRMED defects only. -->

## Where the client's own status does not hold
<!-- Only for a re-validation. Items the client records as remediated that the
     observed behaviour does not support, and the evidence for each. -->

## Finding detail
<!-- One section per DISTINCT DEFECT, not per test case.
### <ID> -- <TITLE>
Severity / Category / CWE / OWASP / Affected endpoints / Occurrences / Cases
**Description** what was observed, factually.
**Impact** what it means for this system, specifically.
**Recommendation** what to change.
**Evidence** file paths, with the capture method stated. -->

## Unresolved
<!-- Accepted without error, but impact not provable from outside. Real, and
     NOT counted as a confirmed defect. Say what would be needed to resolve it. -->

## Controls verified as present
<!-- REQUIRED where any control held. Evidence that a control works is part of
     the result, and distinguishes a tested control from an untested one. -->

## Residual and newly identified issues
<!-- Raised by this assessment and not in any prior log. Mark each Confirmed or
     Advisory. -->

## Controls that improved and are not in the issue log
<!-- Only for a re-validation. Improvements observed that no finding tracks. -->

## Coverage limitations -- what this assessment did NOT establish
<!-- REQUIRED. The report is not issuable without it.
     - Baseline calibration result.
     - What was out of scope and therefore untested.
     - What was blocked and therefore unreached.
     - Which remediation items are NOT externally testable (documentation,
       internal process) versus not met.
     - Which items are RISK ACCEPTED -- a decision, not a remediation, and
       never closed as one.
     - Any payload class whose results are unreliable (e.g. proxy fidelity). -->

## Scope note
<!-- REQUIRED. Rules of engagement, exclusions, and the authorisation under
     which any state-mutating or volumetric testing was performed. -->

## Evidence index
<!-- Run directory, manifest hash, and per-finding evidence paths with capture
     method. -->
