# Methodology

## Principles

**Declare the expectation before you know the result.** Every case states what a
correctly implemented target must do. Deciding afterwards is how an assessment
rationalises whatever it happened to observe.

**Measure control presence, not pass/fail.** Attribute the response to the layer
that answered it, then ask whether a refusal at that layer satisfies the
expectation. Record how deep the control sits.

**An unreached test is not a result.** Blocked, skipped and errored cases are
counted separately and never folded into a pass rate.

**Calibrate the oracle.** A run starts with well-formed requests that must
succeed. If they do not, the negative results are evidence of a broken harness,
not of a remediated target.

**State what you did not establish.** Every assessment has limits. The section
that records them is the first casualty of time pressure, so the framework
refuses to issue a report without it.

## Phases

Ordered so state mutation increases monotonically. A run can stop at any
boundary and everything executed so far was the less invasive work.

### P1 -- Function-level authorization (API5)
Can an identity with the wrong role perform a privileged action? Requests are
deliberately **well formed**: a malformed request that is refused proves nothing
about authorization, because it may have died in validation. Only a perfectly
valid request isolates the role check.

### P2 -- Authentication (API2)
Can an invalid, absent, mismatched, empty or duplicated credential
authenticate? Includes credential *rebinding*: each credential individually
valid but belonging to different subjects. A service that validates them
independently rather than as a bound set accepts the combination.

### P3 -- Object and identifier binding (API1)
Are the identifiers in a request validated against each other and against the
caller's entitlement? A request carrying both a resource identifier and a
correlation identifier, with the two never checked against one another, is a
common and high-severity defect.

### P4 -- Business logic (API6)
Can a caller assert an outcome they should not control? Contradictory state,
forced status transitions, and descriptive fields that influence decisioning.

### P5 -- Mass assignment (API3)
Do undeclared properties bind to domain objects? Status, privilege, ownership
and accounting fields injected alongside the documented schema.

### P6 -- Breadth (API8)
Shared request handling means a defect found on one endpoint usually exists on
all of them -- and a fix applied to only one endpoint is a common remediation
failure. Breadth proves consistency either way.

### P7 -- Surface and trust (API7/API8)
Verb tunnelling, host and forwarding header overrides, and source-address
headers presented as identity.

## Payload families

| Family | Probes |
|---|---|
| A | cross-namespace identifier substitution |
| B | status-flag contradiction |
| C | injection into the identifier field (SQL, XSS, traversal, CRLF, template, EL, command, NoSQL, LDAP, NUL, log forging, bidi) |
| D | type confusion |
| E | structural abuse: omission, wrong container, prototype pollution, duplicate members, deep nesting, malformed JSON |
| F | resource limits |
| G | identifier integrity and replay, including case sensitivity |
| H | media type |
| I | HTTP method, including TRACE |
| J | credential removal, mismatch, duplication, emptiness, case variation |

Family J's header-case-variation case expects **acceptance**: HTTP header names
are case-insensitive, so acceptance is correct behaviour. Declaring it a
rejection case would record correct behaviour as a win.

## Second-order follow-up probes

Questions a first run *raises* rather than answers. Each exists because an
obvious-looking result turned out to be incomplete.

| Probe | Question |
|---|---|
| `case_sensitivity` | Is a uniqueness check case-sensitive? "Duplicate rejected" does not mean duplicate detection works. |
| `scope_of_fix` | Was a sanitisation fix applied to one field or all of them? |
| `cross_endpoint` | Is a uniqueness constraint global or per-endpoint? |
| `per_node` | Is a limit enforced on every node of a load-balanced pool? |
| `credential_lifecycle` | Is an old credential still accepted? (Lifetime and revocation are *not* externally observable.) |
| `response_headers` | Which security headers are present; which advertise the stack? |
| `method_and_media` | Are method and media-type rules consistent across every endpoint? |

## Re-validating previously reported findings

1. Verdicts come **only** from observed responses. The client's own remediation
   status column is never consulted by the tooling.
2. Baseline calibration is mandatory.
3. Remediation items are typed: `observable`, `not_externally_testable`
   (documentation and internal process -- no verdict possible), and
   `risk_accepted` (a decision, not a remediation, and never closed as one).
4. When an item says "apply consistently across all endpoints", the coverage
   matrix is computed and missing cells are generated rather than inferred.

## Evidence

Every case produces its request bytes, full response, and wire trace, under a
timestamped run directory with a SHA-256 manifest. The capture method travels
with the record.

**Transport-layer findings cannot be captured through an intercepting proxy.**
The proxy terminates TLS and presents its own client certificate, so a
"no client certificate" test silently acquires one and the finding stops
reproducing. Capture those direct and label them so.

## Scope

Rules of engagement are enforced by the tooling, not remembered by the operator.
Cases declare attributes; the policy denies classes; permitting a class requires
a recorded authorisation naming who approved it, when, and against what
reference.
