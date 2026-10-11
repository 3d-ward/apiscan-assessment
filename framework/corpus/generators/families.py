"""Payload-tamper families.

EXTRACTED CAPABILITY (CAP-004). The source's ten families (A-J), rewritten to
operate on declared payload paths so they apply to any JSON API described by a
profile rather than to one specific request shape.

Family letters are kept because they are useful shorthand in a report, and
because an operator who has used the original will recognise them:

  A  cross-resource identifier substitution
  B  state / flag contradiction
  C  injection into the identifier field
  D  type confusion on the identifier field
  E  structural abuse (omission, wrong container, pollution, duplication, depth)
  F  resource limits
  G  identifier integrity and replay
  H  media type
  I  HTTP method
  J  credential and header tampering
"""
import json

from ...methodology import taxonomy as TX
from .. import payload as PL
from ..case import Case
from ..payload import PayloadTemplate


def _tpl(profile, endpoint_id):
    return PayloadTemplate(profile.template_for(endpoint_id), endpoint_id)


def _base(profile, endpoint_id):
    """A well-formed body for *endpoint_id* with fresh synthetic identifiers."""
    tpl = _tpl(profile, endpoint_id)
    ep = profile.endpoint(endpoint_id)
    ident = profile.identifier_for(endpoint_id) if ep.get("identifier_space") else None
    corr = None
    spaces = profile.data.get("identifier_spaces") or {}
    if tpl.correlation_path:
        if "correlation" in spaces:
            corr = profile.generate_identifier("correlation")
        else:
            corr = PL.get(tpl.body, tpl.correlation_path)
    return tpl, tpl.instantiate(identifier=ident, correlation=corr), ident


def _case(cid, endpoint, expectation, desc, body, family, **kw):
    return Case(cid, endpoint, expectation, desc, family=family,
                body=json.dumps(body) if body is not None else None, **kw)


# -- A: cross-resource identifier substitution ---------------------------
def family_a(profile):
    """Send endpoint X's identifier to endpoint Y.

    Detects endpoints that accept an identifier from a namespace they do not
    own -- the shape of a broken object-level authorization defect.
    """
    out = []
    eps = [e for e in profile.endpoint_ids
           if profile.endpoint(e).get("identifier_space")]
    n = 0
    for target in eps:
        tpl = _tpl(profile, target)
        t_space = profile.endpoint(target)["identifier_space"]
        for other in eps:
            if other == target:
                continue
            o_space = profile.endpoint(other)["identifier_space"]
            if o_space == t_space:
                continue        # same namespace: not a substitution
            n += 1
            foreign = profile.generate_identifier(o_space)
            _, base, _ = _base(profile, target)
            body = PL.set_(base, tpl.identifier_path, foreign)
            out.append(_case(
                "A%02d" % n, target, "reject",
                "Identifier from namespace %r (endpoint %r) submitted to %r"
                % (o_space, other, target), body, "A",
                payload_class="identifier", severity_if_accepted="High",
                state_mutating=True, owasp="API1:2023",
                notes="identifier spaces %r vs %r" % (o_space, t_space)))
    return out


# -- B: state / flag contradiction ---------------------------------------
def family_b(profile):
    """Contradictory status fields.

    Generated only where the profile declares a status flag, since the family
    is meaningless otherwise. Each variant derives a FRESH base so no two
    cases share a correlation identifier.
    """
    out = []
    n = 0
    for ep in profile.endpoint_ids:
        tpl = _tpl(profile, ep)
        if not tpl.status_flag_path:
            continue
        variants = [
            ("flag false with no error supplied",
             [(tpl.status_flag_path, False)], "Medium"),
            ("flag true while the error field reports a failure",
             [(tpl.status_flag_path, True),
              (tpl.error_path, "SYNTH-ERROR: operation refused")], "Medium"),
            ("flag as the string 'true' rather than a boolean",
             [(tpl.status_flag_path, "true")], "Low"),
            ("flag as integer 1 rather than a boolean",
             [(tpl.status_flag_path, 1)], "Low"),
        ]
        for desc, sets, sev in variants:
            if any(path is None for path, _ in sets):
                continue
            _, body, _ = _base(profile, ep)
            for path, value in sets:
                body = PL.set_(body, path, value)
            n += 1
            out.append(_case("B%02d" % n, ep, "reject",
                             "%s on %r" % (desc, ep), body, "B",
                             payload_class="structure",
                             severity_if_accepted=sev, state_mutating=True,
                             owasp="API6:2023"))
    return out


# -- C: injection into the identifier field ------------------------------
def family_c(profile, endpoints=None):
    out = []
    eps = endpoints or profile.endpoint_ids[:1]
    n = 0
    for ep in eps:
        tpl = _tpl(profile, ep)
        for label, vector, pclass, sev, note in TX.injection_vectors(False):
            n += 1
            _, base, _ = _base(profile, ep)
            body = PL.set_(base, tpl.identifier_path, vector)
            out.append(_case(
                "C%02d" % n, ep, "reject",
                "%s payload in %s on %r" % (label, tpl.identifier_path, ep),
                body, "C", payload_class="injection", severity_if_accepted=sev,
                state_mutating=False, owasp="API8:2023", notes=note,
                submitted_identifier=vector if isinstance(vector, str) else None,
                markers=["49"] if label.startswith("Template") else []))
    return out


# -- D: type confusion ---------------------------------------------------
def family_d(profile, endpoints=None):
    out = []
    eps = endpoints or profile.endpoint_ids[:1]
    n = 0
    for ep in eps:
        tpl = _tpl(profile, ep)
        for label, value, sev in TX.TYPE_VECTORS:
            n += 1
            _, base, _ = _base(profile, ep)
            body = PL.set_(base, tpl.identifier_path, value)
            out.append(_case("D%02d" % n, ep, "reject",
                             "%s as %s on %r" % (tpl.identifier_path, label, ep),
                             body, "D", payload_class="structure",
                             severity_if_accepted=sev, state_mutating=False,
                             owasp="API8:2023"))
    return out


# -- E: structural abuse -------------------------------------------------
def family_e(profile, endpoints=None):
    """Structural abuse.

    ``add`` takes a *mutation callable* rather than a prebuilt body, so each
    case is built from a freshly generated base. Sharing one base would reuse
    a correlation identifier across every case in the family.
    """
    out = []
    eps = endpoints or profile.endpoint_ids[:1]
    counter = [0]
    for ep in eps:
        tpl = _tpl(profile, ep)

        def add(desc, mutate, sev, pclass="structure", **kw):
            counter[0] += 1
            _, fresh, _ = _base(profile, ep)
            produced = mutate(fresh)
            body = produced if isinstance(produced, str) else json.dumps(produced)
            out.append(Case(
                "E%02d" % counter[0], ep, "reject", "%s on %r" % (desc, ep),
                family="E", body=body, payload_class=pclass,
                severity_if_accepted=sev, state_mutating=False,
                owasp="API8:2023", **kw))

        for path in tpl.declared_paths():
            add("required field %r omitted" % path,
                lambda b, p=path: PL.remove(b, p), "Medium")
        parent = PL.parent_path(tpl.identifier_path)
        if parent:
            add("container %r omitted entirely" % parent,
                lambda b, p=parent: PL.remove(b, p), "Medium")
        add("empty JSON object", lambda b: {}, "Low")
        add("JSON array in place of an object", lambda b: [b], "Medium")
        # json.dumps so the body is a VALID JSON string literal. Returning a
        # bare Python string here would be treated as a raw body and emit
        # unquoted text -- malformed JSON in a case that is meant to test
        # container-type handling, not parser tolerance.
        add("JSON string in place of an object",
            lambda b: json.dumps("not-an-object"), "Medium")

        for key in TX.POLLUTION_KEYS:
            def pollute(b, k=key):
                merged = dict(b) if isinstance(b, dict) else {}
                merged[k] = {"isAdmin": True}
                return merged
            add("prototype pollution via %r" % key, pollute, "High")

        # Duplicate member names must be emitted raw: json.dumps cannot
        # represent a document with the same key twice, yet which value a
        # parser keeps is exactly the behaviour under test.
        if tpl.status_flag_path and "." not in tpl.status_flag_path:
            flag = tpl.status_flag_path

            def duplicate(b, f=flag):
                if not isinstance(b, dict):
                    return json.dumps(b)
                return '{%s,"%s":true,"%s":false}' % (json.dumps(b)[1:-1], f, f)
            add("duplicate JSON member %r (true then false)" % flag,
                duplicate, "Medium")

        def nest(b):
            inner = {"end": True}
            for _ in range(TX.NESTING_DEPTH):
                inner = {"n": inner}
            merged = dict(b) if isinstance(b, dict) else {}
            merged["nested"] = inner
            return merged
        add("%d-level nested object" % TX.NESTING_DEPTH, nest, "Medium",
            pclass="malformed", risk_classes=["volumetric"])

        add("truncated JSON",
            lambda b: json.dumps(b)[:max(1, len(json.dumps(b)) // 2)], "Low",
            pclass="malformed")
        add("trailing comma",
            lambda b: json.dumps(b).rstrip("}") + ",}", "Low",
            pclass="malformed")
        add("escaped NUL inside a JSON string",
            lambda b, p=tpl.identifier_path:
                json.dumps(PL.set_(b, p, "SYNTH" + chr(0) + "0001")),
            "Medium", pclass="malformed")
    return out


# -- F: resource limits --------------------------------------------------
def family_f(profile, endpoints=None):
    out = []
    eps = endpoints or profile.endpoint_ids[:1]
    n = 0
    for ep in eps:
        tpl = _tpl(profile, ep)
        targets = [(tpl.identifier_path, "identifier")]
        if tpl.note_path:
            targets.append((tpl.note_path, "note"))
        for path, label in targets:
            for _vname, size, sev, note in TX.OVERSIZE_VECTORS[:2]:
                n += 1
                _, base, _ = _base(profile, ep)
                out.append(_case(
                    "F%02d" % n, ep, "reject",
                    "%s field %r set to %d characters on %r"
                    % (label, path, size, ep),
                    PL.set_(base, path, "A" * size), "F",
                    payload_class="oversize", severity_if_accepted=sev,
                    state_mutating=False, owasp="API4:2023",
                    risk_classes=["volumetric"], notes=note))
        if tpl.correlation_path:
            n += 1
            _, base, _ = _base(profile, ep)
            out.append(_case(
                "F%02d" % n, ep, "reject",
                "correlation field %r set to 1000 characters on %r"
                % (tpl.correlation_path, ep),
                PL.set_(base, tpl.correlation_path, "c" * 1000), "F",
                payload_class="oversize", severity_if_accepted="Low",
                state_mutating=False, owasp="API4:2023",
                risk_classes=["volumetric"]))
    return out


# -- G: identifier integrity and replay ----------------------------------
def family_g(profile, endpoints=None, replay_identifier=None):
    out = []
    eps = endpoints or profile.endpoint_ids[:1]
    n = 0
    for ep in eps:
        tpl = _tpl(profile, ep)
        if tpl.correlation_path:
            variants = [
                ("non-hexadecimal characters", lambda c: "z" * max(8, len(c)),
                 "Medium"),
                ("truncated to 8 characters", lambda c: c[:8] or "deadbeef",
                 "Low"),
                ("one character short", lambda c: c[:-1] or "short", "Low"),
                ("one character long", lambda c: c + "a", "Low"),
                ("leading whitespace", lambda c: " " + c[:-1], "Low"),
                ("uppercased", lambda c: c.upper(), "Medium"),
            ]
            for desc, transform, sev in variants:
                n += 1
                _, base, _ = _base(profile, ep)
                corr = str(PL.get(base, tpl.correlation_path) or "")
                out.append(_case(
                    "G%02d" % n, ep, "reject",
                    "correlation identifier with %s on %r" % (desc, ep),
                    PL.set_(base, tpl.correlation_path, transform(corr)), "G",
                    payload_class="identifier", severity_if_accepted=sev,
                    state_mutating=False, owasp="API8:2023",
                    notes="uppercase acceptance reveals a case-sensitive "
                          "uniqueness check" if desc == "uppercased" else ""))
        if replay_identifier and tpl.correlation_path:
            n += 1
            _, base, _ = _base(profile, ep)
            out.append(_case(
                "G%02d" % n, ep, "reject",
                "replay of a previously processed correlation identifier on %r" % ep,
                PL.set_(base, tpl.correlation_path, replay_identifier), "G",
                payload_class="identifier", severity_if_accepted="Medium",
                state_mutating=True, owasp="API6:2023",
                notes="idempotency / replay protection"))
    return out


# -- H: media type -------------------------------------------------------
def family_h(profile, endpoints=None):
    out = []
    eps = endpoints or profile.endpoint_ids[:1]
    n = 0
    for ep in eps:
        for ctype, sev in TX.CONTENT_TYPES:
            n += 1
            _, base, _ = _base(profile, ep)
            out.append(Case(
                "H%02d" % n, ep, "reject",
                "JSON body sent with Content-Type %r on %r"
                % (ctype or "(absent)", ep),
                family="H", body=json.dumps(base), content_type=ctype,
                payload_class="media_type", severity_if_accepted=sev,
                state_mutating=False, owasp="API8:2023"))
    return out


# -- I: HTTP method ------------------------------------------------------
def family_i(profile, endpoints=None):
    out = []
    eps = endpoints or profile.endpoint_ids[:1]
    n = 0
    for ep in eps:
        declared = [m.upper() for m in (profile.endpoint(ep).get("methods")
                                        or ["POST"])]
        for method, sev in TX.UNEXPECTED_METHODS:
            if method in declared:
                continue
            n += 1
            _, base, _ = _base(profile, ep)
            out.append(Case(
                "I%02d" % n, ep, "reject",
                "%s on %r, which declares only %s"
                % (method, ep, "/".join(declared)),
                family="I", body=json.dumps(base), method=method,
                payload_class="method", severity_if_accepted=sev,
                state_mutating=(method in ("DELETE", "PUT", "PATCH")),
                owasp="API8:2023",
                notes="TRACE answering 200 is a misconfiguration"
                      if method == "TRACE" else ""))
    return out


# -- J: credential and header tampering ----------------------------------
def family_j(profile, auth_provider, endpoints=None):
    """Credential removal, mismatch, duplication and case variation.

    Header names are discovered from the auth provider rather than assumed, so
    this family works for header-token, bearer and basic schemes alike.
    """
    out = []
    eps = endpoints or profile.endpoint_ids
    counter = [0]
    primary = auth_provider.default_identity
    primary_headers = auth_provider.headers_for(primary)
    cred_names = list(primary_headers)

    first_ep = eps[0]

    def add(desc, overrides, sev, expectation="reject", **kw):
        # A FRESH body per case. Sharing one body would reuse the same
        # correlation identifier across every case, so any target with replay
        # protection refuses everything after the first and the entire family
        # reports as a business-layer rejection instead of testing credentials.
        counter[0] += 1
        _, fresh, _ = _base(profile, first_ep)
        out.append(Case("J%02d" % counter[0], first_ep, expectation, desc,
                        family="J", body=json.dumps(fresh),
                        header_overrides=overrides,
                        payload_class="auth", severity_if_accepted=sev,
                        state_mutating=False, owasp="API2:2023", **kw))

    for name in cred_names:
        add("credential header %r removed" % name, {name: None}, "High")
    if len(cred_names) > 1:
        add("all credential headers removed",
            dict.fromkeys(cred_names, None), "High")

    others = [i for i in sorted(auth_provider.identities) if i != primary]
    for other in others[:2]:
        other_headers = auth_provider.headers_for(other)
        shared = [nm for nm in cred_names if nm in other_headers]
        if len(cred_names) > 1 and shared:
            add("credential %r taken from identity %r while the remaining "
                "headers stay those of %r" % (shared[0], other, primary),
                {shared[0]: other_headers[shared[0]]}, "High",
                notes="credentials must be bound to each other, not merely "
                      "individually valid")

    for name in cred_names:
        if primary_headers.get(name) is None:
            continue
        add("duplicate %r header: invalid value first, valid second" % name,
            {name: ["SYNTH-INVALID-CREDENTIAL", primary_headers[name]]}, "High",
            notes="a server that selects the permissive value accepts an "
                  "invalid credential alongside a valid one")
        add("duplicate %r header: valid value first, invalid second" % name,
            {name: [primary_headers[name], "SYNTH-INVALID-CREDENTIAL"]}, "High")
        add("credential %r present but empty" % name, {name: ""}, "High")
        # Case variation is a baseline, not a defect: HTTP header names are
        # case-insensitive, so acceptance here is CORRECT behaviour. Declared
        # as "accept" so a rejection shows up as OVER-BLOCKED instead of being
        # silently recorded as a win.
        add("credential header name case-varied to %r" % name.upper(),
            {name: None, name.upper(): primary_headers[name]},
            "Informational", expectation="accept",
            notes="baseline: header names are case-insensitive, so this must "
                  "still authenticate")

    # Unauthenticated access to every endpoint, not just the first.
    for ep in eps:
        _, b2, _ = _base(profile, ep)
        counter[0] += 1
        out.append(Case("J%02d" % counter[0], ep, "reject",
                        "no credential headers on %r" % ep, family="J",
                        body=json.dumps(b2),
                        header_overrides=dict.fromkeys(cred_names, None),
                        payload_class="auth", severity_if_accepted="High",
                        state_mutating=False, owasp="API2:2023"))
    return out


ALL_FAMILIES = {
    "A": family_a, "B": family_b, "C": family_c, "D": family_d,
    "E": family_e, "F": family_f, "G": family_g, "H": family_h,
    "I": family_i, "J": family_j,
}


def generate(profile, auth_provider=None, families=None, endpoints=None,
             replay_identifier=None):
    """Generate the selected families for *profile*.

    Case ids are namespaced by family letter, then renumbered globally so the
    corpus has stable, unique ids regardless of which families were selected.
    """
    want = [f.upper() for f in (families or sorted(ALL_FAMILIES))]
    cases = []
    for letter in want:
        fn = ALL_FAMILIES.get(letter)
        if fn is None:
            raise KeyError("unknown family %r (known: %s)"
                           % (letter, ", ".join(sorted(ALL_FAMILIES))))
        if letter == "J":
            if auth_provider is None:
                continue
            cases.extend(fn(profile, auth_provider, endpoints=endpoints))
        elif letter in ("A", "B"):
            cases.extend(fn(profile))
        elif letter == "G":
            cases.extend(fn(profile, endpoints=endpoints,
                            replay_identifier=replay_identifier))
        else:
            cases.extend(fn(profile, endpoints=endpoints))
    return cases
