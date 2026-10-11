"""Assessment phases.

EXTRACTED CAPABILITY (CAP-005). The source's phase model, generalised and made
declarative.

The ordering is the important part and it is not alphabetical: phases are
sequenced so that **state mutation increases monotonically**. A run can
therefore stop at any point and everything executed so far will have been the
less invasive work. Authorization and authentication come first because they
need only a well-formed request; business-logic and mass-assignment abuse come
later because they can change records.

``ordering_weight`` is the sort key. ``default_mutating`` is the fail-safe
annotation applied to generated cases in that phase unless a generator knows
better.
"""

PHASES = [
    {"id": "P1", "name": "Function-level authorization",
     "owasp": "API5:2023 Broken Function Level Authorization",
     "ordering_weight": 10, "default_mutating": False,
     "question": "Can an identity with the wrong role perform a privileged action?",
     "objective": "Confirm every endpoint enforces role separation, including "
                  "when the request itself is perfectly well formed."},
    {"id": "P2", "name": "Authentication",
     "owasp": "API2:2023 Broken Authentication",
     "ordering_weight": 20, "default_mutating": False,
     "question": "Can an invalid, absent, mismatched or duplicated credential "
                 "still authenticate?",
     "objective": "Confirm credentials are validated, bound to their subject, "
                  "and that duplicate or differently-cased headers cannot "
                  "smuggle a permissive value."},
    {"id": "P3", "name": "Object and identifier binding",
     "owasp": "API1:2023 Broken Object Level Authorization",
     "ordering_weight": 30, "default_mutating": True,
     "question": "Are the identifiers in a request validated against each "
                 "other and against the caller's entitlement?",
     "objective": "Detect identifiers accepted out of their own namespace, and "
                  "correlation identifiers never checked against the resource "
                  "they claim to describe."},
    {"id": "P4", "name": "Business logic",
     "owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows",
     "ordering_weight": 40, "default_mutating": True,
     "question": "Can a caller drive a business outcome they should not be "
                 "able to assert?",
     "objective": "Probe contradictory state, forced status transitions and "
                  "fields that influence decisioning."},
    {"id": "P5", "name": "Mass assignment",
     "owasp": "API3:2023 Broken Object Property Level Authorization",
     "ordering_weight": 50, "default_mutating": True,
     "question": "Do undeclared properties bind to domain objects?",
     "objective": "Inject privilege and status properties alongside the "
                  "documented schema and observe whether they are rejected, "
                  "ignored or honoured."},
    {"id": "P6", "name": "Breadth",
     "owasp": "API8:2023 Security Misconfiguration",
     "ordering_weight": 60, "default_mutating": False,
     "question": "Does every endpoint behave consistently, not just the "
                 "well-trodden one?",
     "objective": "Apply the core payload families across all remaining "
                  "endpoints, because shared request handling means a defect "
                  "on one endpoint usually exists on the others."},
    {"id": "P7", "name": "Surface and trust",
     "owasp": "API7:2023 Server Side Request Forgery / API8 Misconfiguration",
     "ordering_weight": 70, "default_mutating": False,
     "question": "Does the service derive any trust from data the client "
                 "controls?",
     "objective": "Verb tunnelling, host and forwarding header spoofing, and "
                  "source-address headers presented as identity."},
]

BY_ID = {p["id"]: p for p in PHASES}
ORDERED_IDS = [p["id"] for p in sorted(PHASES, key=lambda p: p["ordering_weight"])]


def get(phase_id):
    if phase_id not in BY_ID:
        raise KeyError("unknown phase %r (known: %s)"
                       % (phase_id, ", ".join(ORDERED_IDS)))
    return BY_ID[phase_id]


def ordered(up_to=None):
    """Phases in execution order, optionally truncated at *up_to* inclusive."""
    ids = list(ORDERED_IDS)
    if up_to:
        if up_to not in ids:
            raise KeyError("unknown phase %r" % up_to)
        ids = ids[:ids.index(up_to) + 1]
    return [BY_ID[i] for i in ids]


def is_monotonic_in_mutation():
    """Assert the ordering invariant: no non-mutating phase follows a mutating one
    unless it is breadth/surface work explicitly placed later.

    Used by the test suite to stop the ordering being casually reshuffled -- the
    sequence is a safety property, not a presentation choice.
    """
    weights = [p["ordering_weight"] for p in
               sorted(PHASES, key=lambda p: p["ordering_weight"])]
    return weights == sorted(weights) and len(set(weights)) == len(weights)
