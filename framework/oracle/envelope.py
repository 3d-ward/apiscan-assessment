"""Application-envelope decoding.

EXTRACTED CAPABILITY (CAP-008). Some APIs answer HTTP 200 for everything and
signal the real outcome inside the body. For those, the HTTP status says only
that the request was received; the application layer decides accept vs reject.
Reading the status alone would score every rejected malformed input as accepted.

ENGINEERING IMPROVEMENT over the source: the body is parsed as JSON and read by
declared path, falling back to a regex only when the body is malformed. The
source used regex exclusively, which mis-read nested envelopes and could match
a field of the same name nested anywhere in the document.
"""
import json
import re


def _dig(obj, path):
    """Fetch a dotted path. Supports ``a.b[0].c``. Returns None if absent."""
    cur = obj
    for part in re.split(r"\.", path):
        if not part:
            continue
        m = re.match(r"^([^\[\]]*)((?:\[\d+\])*)$", part)
        if not m:
            return None
        key, idx = m.group(1), m.group(2)
        if key:
            if not isinstance(cur, dict) or key not in cur:
                return None
            cur = cur[key]
        for n in re.findall(r"\[(\d+)\]", idx or ""):
            if not isinstance(cur, list) or int(n) >= len(cur):
                return None
            cur = cur[int(n)]
    return cur


def _regex_field(text, field):
    """Last-resort extraction from a malformed body."""
    leaf = field.split(".")[-1].split("[")[0]
    m = re.search(r'"%s"\s*:\s*"([^"]*)"' % re.escape(leaf), text or "")
    if m:
        return m.group(1)
    m = re.search(r'"%s"\s*:\s*(true|false|null|-?\d+(?:\.\d+)?)'
                  % re.escape(leaf), text or "")
    return m.group(1) if m else None


class EnvelopeResult(object):
    def __init__(self, present, code, remark, detail, parsed, source):
        self.present = present
        self.code = code
        self.remark = remark
        self.detail = detail
        self.parsed = parsed
        self.source = source          # "json", "regex" or "absent"

    def __repr__(self):
        return "<Envelope present=%s code=%r via=%s>" % (
            self.present, self.code, self.source)


ABSENT = EnvelopeResult(False, None, "", "", None, "absent")


def decode(body, spec):
    """Decode an application envelope from *body* per *spec*.

    *spec* is the profile's ``response_model.envelope`` mapping, or None when
    the API uses HTTP status codes honestly.
    """
    if not spec or not body:
        return ABSENT

    code_path = spec.get("code_path")
    if not code_path:
        return ABSENT

    parsed = None
    text = body if isinstance(body, str) else str(body)
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None

    source = "absent"
    code = remark = data = None
    if parsed is not None:
        code = _dig(parsed, code_path)
        if code is not None:
            source = "json"
            if spec.get("remark_path"):
                remark = _dig(parsed, spec["remark_path"])
            if spec.get("data_path"):
                data = _dig(parsed, spec["data_path"])
    if source == "absent":
        code = _regex_field(text, code_path)
        if code is not None:
            source = "regex"
            if spec.get("remark_path"):
                remark = _regex_field(text, spec["remark_path"])

    if code is None:
        return ABSENT

    code = str(code)
    remark = "" if remark is None else str(remark)
    detail = remark
    if data not in (None, "null", [], {}):
        rendered = data if isinstance(data, str) else json.dumps(data)
        detail = (detail + " " + rendered).strip()

    return EnvelopeResult(True, code, remark, detail, parsed, source)


def is_success(result, spec):
    """True when the envelope code is one the profile declares as success."""
    if not result.present or not spec:
        return False
    return result.code in [str(v) for v in (spec.get("success_values") or [])]


def is_auth_failure(result, spec):
    if not result.present or not spec:
        return False
    return result.code in [str(v) for v in (spec.get("auth_failure_values") or [])]
