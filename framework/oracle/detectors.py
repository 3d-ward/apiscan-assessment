"""Response detectors: information disclosure and payload reflection.

EXTRACTED CAPABILITY (CAP-009, CAP-010).

Rules live in ``rules/*.json`` rather than in code, so an engagement can add a
signature for a stack it meets without editing the engine -- and so the rule set
can be reviewed as data.

Reflection detection (CAP-010) is extended here: the source compared the
submitted value verbatim only, which misses the common case of a payload echoed
back HTML-, URL- or JSON-escaped. An escaped echo is still a reflection and
often still exploitable, so encoded variants are compared too and the encoding
is reported.
"""
import html
import json
import os
import re
import urllib.parse

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

_FLAG_MAP = {"i": re.I, "m": re.M, "s": re.S, "x": re.X}


class Rule(object):
    def __init__(self, spec):
        self.id = spec["id"]
        self.name = spec["name"]
        self.severity = spec.get("severity", "Informational")
        self.cwe = spec.get("cwe", "")
        flags = 0
        for ch in spec.get("flags", ""):
            flags |= _FLAG_MAP.get(ch, 0)
        self.regex = re.compile(spec["pattern"], flags)

    def scan(self, text):
        m = self.regex.search(text or "")
        return m.group(0)[:160] if m else None

    def __repr__(self):
        return "<Rule %s %s>" % (self.id, self.severity)


class Hit(object):
    def __init__(self, rule_id, name, severity, cwe, excerpt, kind="disclosure"):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.cwe = cwe
        self.excerpt = excerpt
        self.kind = kind

    def as_dict(self):
        return dict(rule_id=self.rule_id, name=self.name, severity=self.severity,
                    cwe=self.cwe, excerpt=self.excerpt, kind=self.kind)

    def __repr__(self):
        return "<Hit %s %s>" % (self.rule_id, self.severity)


def load_rules(directory=None, filenames=None):
    """Load every rule file in *directory* (default: the bundled rules)."""
    directory = directory or RULES_DIR
    rules = []
    names = filenames or sorted(
        f for f in os.listdir(directory) if f.endswith(".json"))
    for fn in names:
        with open(os.path.join(directory, fn)) as fh:
            spec = json.load(fh)
        for r in spec.get("rules", []):
            rules.append(Rule(r))
    seen = {}
    for r in rules:
        if r.id in seen:
            raise ValueError("duplicate detector rule id %r" % r.id)
        seen[r.id] = True
    return rules


def scan_disclosure(text, rules):
    """Return a Hit for every disclosure rule that matches."""
    hits = []
    for rule in rules:
        excerpt = rule.scan(text)
        if excerpt:
            hits.append(Hit(rule.id, rule.name, rule.severity, rule.cwe,
                            excerpt, "disclosure"))
    return hits


def _encodings(value):
    """Encoded variants of *value* that still constitute a reflection."""
    out = [("verbatim", value)]
    esc = html.escape(value, quote=True)
    if esc != value:
        out.append(("html-escaped", esc))
    quoted = urllib.parse.quote(value, safe="")
    if quoted != value:
        out.append(("url-encoded", quoted))
    jsonish = json.dumps(value)[1:-1]
    if jsonish != value:
        out.append(("json-escaped", jsonish))
    upper, lower = value.upper(), value.lower()
    if upper != value:
        out.append(("uppercased", upper))
    if lower != value:
        out.append(("lowercased", lower))
    return out


def scan_reflection(submitted, text, min_length=7, payload_class="benign"):
    """Detect *submitted* echoed back in *text*, verbatim or encoded.

    The length floor avoids matching short values that could coincide with
    ordinary response content. Severity escalates when the reflected value was
    an injection payload, because an echoed injection string is evidence the
    input reaches an output context unsanitised.
    """
    if not submitted or not text:
        return None
    value = submitted if isinstance(submitted, str) else str(submitted)
    if len(value) < min_length:
        return None
    for kind, variant in _encodings(value):
        if variant and variant in text:
            if payload_class == "injection":
                return Hit("REFLECT-INJECTION",
                           "Injection payload reflected in response (%s)" % kind,
                           "High", "CWE-79: Improper Neutralization of Input "
                           "During Web Page Generation", variant[:160],
                           "reflection")
            return Hit("REFLECT-INPUT",
                       "Submitted input reflected in response (%s)" % kind,
                       "Low", "CWE-200: Exposure of Sensitive Information",
                       variant[:160], "reflection")
    return None
