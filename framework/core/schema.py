"""A small JSON Schema validator covering the subset the framework needs.

``jsonschema`` is not available in the target environment and the no-download
policy forbids fetching it, so this implements the keywords the framework's own
schemas use and nothing more. It reports *all* violations with JSON-pointer
paths rather than stopping at the first, because a half-validated config wastes
an operator's time.

Supported: type, required, properties, additionalProperties, enum, items,
minItems, pattern, minimum, maximum, minLength, minProperties,
maxProperties, oneOf, anyOf, const,
patternProperties, propertyNames (pattern only), nullable via type lists.
Deliberately unsupported: $ref, allOf, if/then, dependencies, format.
"""
import re

_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "number": (int, float), "integer": int, "null": type(None),
}


def _is_type(value, name):
    if name == "integer":
        # JSON has no int/float distinction, but a bool is not an integer.
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    py = _TYPES.get(name)
    return isinstance(value, py) if py else False


class ValidationError(Exception):
    def __init__(self, errors):
        self.errors = list(errors)
        super(ValidationError, self).__init__(
            "%d schema violation(s):\n  %s"
            % (len(self.errors), "\n  ".join(self.errors)))


def validate(instance, schema, path="$", errors=None, raise_on_error=True):
    """Validate *instance*; return the error list (empty when valid)."""
    top = errors is None
    if errors is None:
        errors = []

    def err(msg):
        errors.append("%s: %s" % (path, msg))

    if "const" in schema and instance != schema["const"]:
        err("must equal %r" % (schema["const"],))

    if "type" in schema:
        allowed = schema["type"]
        allowed = [allowed] if isinstance(allowed, str) else list(allowed)
        if not any(_is_type(instance, t) for t in allowed):
            err("expected type %s, got %s" % ("/".join(allowed),
                                              type(instance).__name__))
            if top and raise_on_error and errors:
                raise ValidationError(errors)
            return errors

    if "enum" in schema and instance not in schema["enum"]:
        err("must be one of %r, got %r" % (schema["enum"], instance))

    for key, pred, desc in (("minimum", lambda v, b: v >= b, "at least"),
                            ("maximum", lambda v, b: v <= b, "at most")):
        if key in schema and isinstance(instance, (int, float)) \
                and not isinstance(instance, bool):
            if not pred(instance, schema[key]):
                err("must be %s %r" % (desc, schema[key]))

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            err("shorter than minLength %d" % schema["minLength"])
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            err("does not match pattern %r" % schema["pattern"])

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            err("needs at least %d item(s)" % schema["minItems"])
        if "items" in schema:
            for i, item in enumerate(instance):
                validate(item, schema["items"], "%s[%d]" % (path, i), errors,
                         raise_on_error=False)

    if isinstance(instance, dict):
        if "minProperties" in schema and len(instance) < schema["minProperties"]:
            err("needs at least %d propert(ies)" % schema["minProperties"])
        if "maxProperties" in schema and len(instance) > schema["maxProperties"]:
            err("allows at most %d propert(ies)" % schema["maxProperties"])
        for name in schema.get("required", ()):
            if name not in instance:
                err("missing required property %r" % name)
        props = schema.get("properties", {})
        pat_props = schema.get("patternProperties", {})
        names_schema = schema.get("propertyNames")
        for name, value in instance.items():
            if names_schema and "pattern" in names_schema:
                if not re.search(names_schema["pattern"], name):
                    err("property name %r does not match %r"
                        % (name, names_schema["pattern"]))
            child = "%s.%s" % (path, name)
            if name in props:
                validate(value, props[name], child, errors, raise_on_error=False)
                continue
            matched = False
            for pat, sub in pat_props.items():
                if re.search(pat, name):
                    validate(value, sub, child, errors, raise_on_error=False)
                    matched = True
            if matched:
                continue
            if schema.get("additionalProperties") is False:
                err("unexpected property %r" % name)
            elif isinstance(schema.get("additionalProperties"), dict):
                validate(value, schema["additionalProperties"], child, errors,
                         raise_on_error=False)

    for key in ("oneOf", "anyOf"):
        if key in schema:
            oks = 0
            for sub in schema[key]:
                if not validate(instance, sub, path, [], raise_on_error=False):
                    oks += 1
            if key == "oneOf" and oks != 1:
                err("must match exactly one of %d subschemas (matched %d)"
                    % (len(schema[key]), oks))
            if key == "anyOf" and oks == 0:
                err("must match at least one of %d subschemas" % len(schema[key]))

    if top and raise_on_error and errors:
        raise ValidationError(errors)
    return errors
