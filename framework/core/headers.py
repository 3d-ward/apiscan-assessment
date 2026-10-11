"""Header mutation.

EXTRACTED CAPABILITY (CAP-003), lifted with its semantics intact.

Four mutation modes drive a large share of the authentication, authorization and
surface test families, so they are kept as one small pure function that can be
exhaustively tested:

  value is None   -> remove the header, matching case-insensitively across every
                     spelling already present. HTTP header names are
                     case-insensitive, so removing only the exact spelling would
                     leave a differently-cased duplicate in place and silently
                     turn an auth-stripping test into a no-op.
  value is a list -> emit the header once per element, in order. Duplicate-header
                     precedence is a real defect class: a server that selects the
                     permissive value lets an invalid credential ride alongside a
                     valid one.
  value is a str  -> replace (or add).
  key absent      -> inherit the base value.
"""


def apply_overrides(base, overrides):
    """Return an ordered list of (name, value) pairs to send.

    *base* and *overrides* are mappings. Neither is modified. Order is
    preserved: a replaced header keeps its original position, because PoC
    evidence is only trustworthy if a re-sent request is byte-identical to the
    one that produced the finding, and header order is part of those bytes.
    """
    pairs = list((base or {}).items())
    appended = []

    for key, value in (overrides or {}).items():
        lowered = key.lower()
        positions = [i for i, (k, _) in enumerate(pairs) if k.lower() == lowered]

        if value is None:
            pairs = [p for p in pairs if p[0].lower() != lowered]
            appended = [p for p in appended if p[0].lower() != lowered]
        elif isinstance(value, (list, tuple)):
            # Duplicates replace any existing spelling and are emitted in order
            # at the first existing position, or appended when new.
            pairs = [p for p in pairs if p[0].lower() != lowered]
            appended = [p for p in appended if p[0].lower() != lowered]
            block = [(key, item) for item in value]
            if positions:
                at = min(positions)
                pairs = pairs[:at] + block + pairs[at:]
            else:
                appended.extend(block)
        else:
            if positions:
                at = min(positions)
                pairs = [p for i, p in enumerate(pairs)
                         if p[0].lower() != lowered or i == at]
                pairs = [(key, value) if p[0].lower() == lowered else p
                         for p in pairs]
            else:
                appended = [p for p in appended if p[0].lower() != lowered]
                appended.append((key, value))

    return pairs + appended


def to_curl_args(pairs, content_type=None):
    """Render header pairs as curl arguments.

    An empty-string content type is sent as a header *suppression*
    (``-H 'Content-Type;'``), which is how curl is told to omit a header it
    would otherwise add by default. That distinction matters: "absent" and
    "empty" are different test cases for media-type validation.
    """
    args = []
    for name, value in pairs:
        args += ["-H", "%s: %s" % (name, value)]
    if content_type is None:
        pass
    elif content_type == "":
        args += ["-H", "Content-Type;"]
    else:
        args += ["-H", "Content-Type: %s" % content_type]
    return args
