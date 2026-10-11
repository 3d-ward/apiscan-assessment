"""Payload template instantiation and mutation.

A payload template is ordinary JSON plus declared paths naming the fields that
carry meaning: the resource identifier, the correlation identifier, the
status flag, the error field. Generators mutate *by path*, so a family such as
"type confusion on the identifier field" is written once and works against any
target whose profile names that path.

This is what replaces the source's hardcoded body structure. There, every
generator knew the shape of one specific API's request.
"""
import copy
import json
import re

SENTINEL_MISSING = object()


def _parse(path):
    """Split ``a.b[0].c`` into ['a', 'b', 0, 'c']."""
    parts = []
    for chunk in path.split("."):
        if not chunk:
            continue
        m = re.match(r"^([^\[\]]*)((?:\[\d+\])*)$", chunk)
        if not m:
            raise ValueError("malformed path segment %r in %r" % (chunk, path))
        if m.group(1):
            parts.append(m.group(1))
        for idx in re.findall(r"\[(\d+)\]", m.group(2) or ""):
            parts.append(int(idx))
    return parts


def get(obj, path, default=None):
    cur = obj
    for part in _parse(path):
        if isinstance(part, int):
            if not isinstance(cur, list) or part >= len(cur):
                return default
            cur = cur[part]
        else:
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
    return cur


def set_(obj, path, value):
    """Set *path* to *value* in a deep copy; returns the copy."""
    out = copy.deepcopy(obj)
    parts = _parse(path)
    cur = out
    for part in parts[:-1]:
        if isinstance(part, int):
            cur = cur[part]
        else:
            if part not in cur or not isinstance(cur[part], (dict, list)):
                cur[part] = {}
            cur = cur[part]
    last = parts[-1]
    if isinstance(last, int):
        cur[last] = value
    else:
        cur[last] = value
    return out


def remove(obj, path):
    """Delete *path* from a deep copy; returns the copy."""
    out = copy.deepcopy(obj)
    parts = _parse(path)
    cur = out
    for part in parts[:-1]:
        if isinstance(part, int):
            if not isinstance(cur, list) or part >= len(cur):
                return out
            cur = cur[part]
        else:
            if not isinstance(cur, dict) or part not in cur:
                return out
            cur = cur[part]
    last = parts[-1]
    if isinstance(last, int):
        if isinstance(cur, list) and last < len(cur):
            del cur[last]
    elif isinstance(cur, dict):
        cur.pop(last, None)
    return out


def parent_path(path):
    parts = path.split(".")
    return ".".join(parts[:-1]) if len(parts) > 1 else ""


class PayloadTemplate(object):
    """A request body plus the declared meaning of its fields."""

    def __init__(self, spec, name="default"):
        self.name = name
        self.spec = spec
        self.body = spec["body"]
        self.identifier_path = spec["identifier_path"]
        self.correlation_path = spec.get("correlation_path")
        self.status_flag_path = spec.get("status_flag_path")
        self.error_path = spec.get("error_path")
        self.note_path = spec.get("note_path")
        self.mutable_paths = list(spec.get("mutable_paths") or [])

    def instantiate(self, identifier=None, correlation=None, **overrides):
        """Build a concrete body."""
        body = copy.deepcopy(self.body)
        if identifier is not None:
            body = set_(body, self.identifier_path, identifier)
        if correlation is not None and self.correlation_path:
            body = set_(body, self.correlation_path, correlation)
        for path, value in overrides.items():
            dotted = path.replace("__", ".")
            body = set_(body, dotted, value)
        return body

    def with_value(self, base_body, path, value):
        return set_(base_body, path, value)

    def without(self, base_body, path):
        return remove(base_body, path)

    def declared_paths(self):
        paths = [self.identifier_path]
        for p in (self.correlation_path, self.status_flag_path,
                  self.error_path, self.note_path):
            if p:
                paths.append(p)
        return paths

    def dumps(self, body):
        return json.dumps(body)
