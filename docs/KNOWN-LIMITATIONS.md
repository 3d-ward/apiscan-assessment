# Known limitations

Stated plainly, because a framework that advertises more than it does produces
assessments that do the same.

## Not verified in the build environment

These ship as code with unit-tested logic, but their runtime path has **not**
been executed here, because the required packages were unavailable under a
no-download policy. They are reported `NOT VERIFIED`, not "passing".

| Capability | Missing dependency | What was verified |
|---|---|---|
| Proxy-window screenshot (`tools/capture/window.py`) | `pyobjc-framework-Quartz` | window-selection logic against synthetic window lists; availability reporting |
| PoC images embedded in the workbook | `Pillow` | the absence is detected and reported in `RenderResult.notes`; paths are referenced instead |
| TLS cipher enumeration | `nmap` / `testssl.sh` | the absence returns `NOT VERIFIED` with a remedy, never a clean result. Verify availability on the host you run from -- this table records the *build* environment, not yours |

Run `./apiscan version` on the machine you are assessing from: it reports which
of these capabilities that host actually has, and what each absence costs. This
table is about a build; that command is about your run.

Install commands are in `dependencies/README.md`.

## Scope of the assessment surface

* **JSON request bodies only.** XML, form-encoded, multipart and GraphQL bodies
  are not generated. An XXE vector exists in the taxonomy but is not emitted
  unless an endpoint declares XML.
* **HTTP/1.1 and HTTP/2 via curl.** No gRPC, WebSocket or server-sent events.
* **Header, bearer and basic authentication.** OAuth2 flows, HMAC request
  signing, and mutual-TLS-as-identity are not implemented as providers; mutual
  TLS is supported at transport level only.
* **No stateful sequencing.** Multi-step business flows and workflow-order abuse
  are not modelled. Each case is independent.
* **No authenticated session management.** No login, token refresh or CSRF
  handling.

## Oracle

* Layer attribution is **heuristic** and status-code driven, refined by a
  declared envelope. An API that signals outcomes in a way the profile does not
  describe will be mis-attributed. The `other` and `UNCLEAR` outcomes exist to
  make that visible rather than to paper over it.
* A `404` with no business marker is `UNCLEAR`, not a pass -- verify the
  endpoint path before drawing a conclusion.
* Severity is assigned by judgement from the case definition. There is no CVSS
  vector support.

## Detectors

* Signatures cover Java, Python, .NET, Node, PHP, Go, Ruby and SQL. A stack
  outside that set may leak without matching a rule. Rules are data; add one.
* Reflection detection compares verbatim, HTML-, URL- and JSON-escaped and
  case-folded variants. Other encodings (double-encoded, unicode-escaped,
  base64) are not compared.
* Detectors read the response body only. Timing, size and behavioural
  side-channels are not analysed; no blind-injection inference is performed.

## Proxy integration

* Fidelity probes cover large bodies, control characters, duplicate headers and
  malformed JSON. A proxy could alter something else and go unnoticed.
* GUI automation for proxy-window capture depends on coordinate offsets that are
  specific to a proxy version and theme. This is mitigated by a calibration
  profile, not solved. Prefer rendered evidence.

## Rate limiting

The probe answers "does throttling exist?" within hard ceilings (200 requests,
16 workers). It deliberately cannot characterise a limit's shape, window or
recovery behaviour -- that would require sustained load.

## Reporting

* Narrative text -- descriptions, impact, recommendations -- is authored per
  engagement. The framework derives counts, endpoints and evidence paths, and
  enforces the presence of the honesty sections; it does not write prose.
* The workbook has one layout.

## Validation

* `tests/security/test_hygiene.py` checks generic properties: no
  credential-shaped literals, reserved hostnames only, documentation addresses
  only, no target constants, scope defaults to deny. It does **not** check for
  any specific client's identifiers, and must not -- embedding such a list here
  would ship the data the framework exists to exclude.
* That check belongs to a separate, confidential validator held by the operator.
  A PASS there means the defined checks completed within their documented scope.
  It is not a mathematical guarantee that no confidential information exists.

## Not implemented

* **No profile importer.** A tool to bootstrap a target profile from an OpenAPI
  document or an exported API collection would be genuinely useful and was
  considered. It is NOT implemented: it was not a capability of the predecessor,
  so building it would be new work presented alongside extracted work. A profile
  is written by hand -- see `docs/USAGE.md`. Recorded here rather than left as an
  empty package implying otherwise.

## Operational

* Working-tree rollback is by snapshot (`./apiscan snapshot`), not by git:
  snapshots exclude evidence and secrets by pattern and carry a hash manifest.
* No concurrency within a scan: cases execute sequentially with a configurable
  delay. This is deliberate -- parallel execution against a live target makes
  rate effects and state interactions much harder to reason about.
* **Evidence is not encrypted at rest.** Run directories are created mode 0700
  and artifacts 0600, and the manifest's `access` block records whether the
  filesystem actually applied that -- but owner-only permissions are not
  encryption. Anyone with root, or with the disk, can read it. Protect the
  engagement directory accordingly, and prefer a full-disk-encrypted volume.
* **POSIX file modes do not exist on Windows.** The restriction that protects
  captured credentials therefore cannot be applied there. The manifest records
  it as `partial` and lists the files, rather than implying a protection that
  was not achieved. Do not hold client evidence on Windows without separate
  filesystem access control.
* **Retention is enforced only when `apiscan purge` is run.** Each run records
  a `retain_until` date; nothing deletes it on that date by itself. A run with
  no recorded retention date is never deleted automatically, deliberately --
  but that also means evidence from before this mechanism existed will sit
  there until someone looks.

## What the newer safeguards do NOT establish

Each of these is a real improvement with a real boundary, and the boundary is
the part that gets forgotten.

* **Redaction is pattern-based, and patterns miss things.** It removes the
  profile's resolved `${ENV:...}` values, credential headers by name, and known
  credential shapes. A secret the target invented and returned in an
  unrecognised shape -- a session identifier in a custom field, a signed URL, a
  base64 blob -- will survive it. **Read a redacted copy before sending it.**
  `--pii` covers e-mail addresses and long digit runs; it is not a data-loss
  prevention system and does not know your client's identifier formats. Declare
  those in the profile's `redaction.patterns`.
* **Literal credential matching needs the environment populated.** After an
  engagement the secrets are rightly cleared, and then only the shape and
  header passes apply. `apiscan redact` says so when it notices; the strongest
  result comes from redacting while the `.env` is still loaded.
* **The scope gate enforces what was authorised, not whether it was wise.**
  It can prove a request was permitted by a recorded authorisation. It cannot
  tell whether the person who signed that authorisation understood what it
  permitted.
* **A mode's ceilings bound a run, not its impact.** Forty requests to the
  wrong endpoint can do more damage than four thousand to the right one. The
  stop conditions react to a target that is already failing; they do not
  predict one that is about to.
* **State verification requires the API to offer a read path**, declared per
  endpoint. Most callback-style APIs do not. Where there is none, the report
  states that whether a request changed anything is unestablished -- which is
  honest, and is also a permanent gap in external testing of such an API.
* **Ownership testing requires resources whose owner is known.** With no
  `controlled_resources` declared, object-level authorisation is simply NOT
  TESTED and the report says so. That is deliberate: inferring ownership from
  a response is unsound, and guessing identifiers against a live system risks
  touching a real customer's record.
* **`reproduced` and `manually-confirmed` confidence are operator assertions.**
  The framework refuses to construct a `DEFECT` from an automated verdict
  alone, which stops the most common overclaim. It cannot verify that a human
  who set `confidence="manually-confirmed"` actually did the work.
* **Header/body separation removes one way a target could choose its own
  classification.** It does not make attribution correct -- attribution remains
  heuristic, as stated above.
* **Passing tests are not correct conclusions.** The suite establishes that the
  oracle classifies a deliberately-wrong loopback mock as intended. It does not
  establish that the classification is right about any real API. See
  `RELEASE.md`, "What a release does NOT establish".
