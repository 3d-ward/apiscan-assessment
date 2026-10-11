import unittest

from tests.support import ROOT  # noqa: F401  (path setup)
from framework.core.schema import ValidationError, validate


class TestSchema(unittest.TestCase):
    SCHEMA = {
        "type": "object", "required": ["a"], "additionalProperties": False,
        "properties": {
            "a": {"type": "string", "minLength": 2},
            "n": {"type": "integer", "minimum": 1, "maximum": 10},
            "l": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "e": {"enum": ["x", "y"]},
            "o": {"type": "object", "minProperties": 1},
        },
    }

    def test_valid(self):
        self.assertEqual(validate({"a": "ok", "n": 3, "l": ["q"], "e": "x",
                                   "o": {"k": 1}}, self.SCHEMA), [])

    def test_reports_every_violation_not_just_the_first(self):
        errors = validate({"a": "x", "n": 0, "l": [], "e": "z", "bad": 1},
                          self.SCHEMA, raise_on_error=False)
        self.assertEqual(len(errors), 5, errors)

    def test_raises_with_pointers(self):
        with self.assertRaises(ValidationError) as ctx:
            validate({"a": "x"}, self.SCHEMA)
        self.assertTrue(any("$.a" in e for e in ctx.exception.errors))

    def test_bool_is_not_integer(self):
        self.assertTrue(validate(True, {"type": "integer"},
                                 raise_on_error=False))

    def test_min_properties(self):
        self.assertTrue(validate({"a": "ok", "o": {}}, self.SCHEMA,
                                 raise_on_error=False))

    def test_pattern_and_const(self):
        self.assertEqual(validate("abc", {"pattern": "^a"},
                                  raise_on_error=False), [])
        self.assertTrue(validate("v1", {"const": "v2"}, raise_on_error=False))

    def test_nested_pointer_path(self):
        schema = {"type": "object", "properties": {
            "inner": {"type": "object", "properties": {
                "deep": {"type": "integer"}}}}}
        errors = validate({"inner": {"deep": "no"}}, schema,
                          raise_on_error=False)
        self.assertIn("$.inner.deep", errors[0])


if __name__ == "__main__":
    unittest.main()
