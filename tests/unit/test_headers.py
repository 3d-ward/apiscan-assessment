import unittest

from tests.support import ROOT  # noqa: F401
from framework.core.headers import apply_overrides, to_curl_args


class TestHeaderMutation(unittest.TestCase):
    BASE = {"x-id": "u", "x-token": "t", "Accept": "*/*"}

    def test_inherit(self):
        self.assertEqual(apply_overrides(self.BASE, {}),
                         [("x-id", "u"), ("x-token", "t"), ("Accept", "*/*")])

    def test_remove_is_case_insensitive(self):
        # A differently-cased duplicate left behind would silently turn an
        # auth-stripping test into a no-op.
        self.assertEqual(apply_overrides({"X-Token": "t"}, {"x-token": None}),
                         [])

    def test_replace_preserves_position(self):
        # PoC evidence is only trustworthy if a re-sent request is
        # byte-identical, and header order is part of those bytes.
        out = apply_overrides(self.BASE, {"x-id": "other"})
        self.assertEqual(out[0], ("x-id", "other"))
        self.assertEqual(len(out), 3)

    def test_duplicate_emits_in_order_at_original_position(self):
        out = apply_overrides(self.BASE, {"x-token": ["bad", "good"]})
        self.assertEqual(out[1:3], [("x-token", "bad"), ("x-token", "good")])

    def test_new_header_is_appended(self):
        out = apply_overrides(self.BASE, {"X-New": "1"})
        self.assertEqual(out[-1], ("X-New", "1"))

    def test_mixed_case_override_replaces_in_place(self):
        out = apply_overrides(self.BASE, {"X-ID": "z"})
        self.assertEqual(out[0], ("X-ID", "z"))
        self.assertEqual(len(out), 3)

    def test_inputs_are_not_mutated(self):
        base = dict(self.BASE)
        apply_overrides(base, {"x-id": None})
        self.assertEqual(base, self.BASE)

    def test_content_type_absent_empty_and_set_are_distinct(self):
        self.assertEqual(to_curl_args([], None), [])
        self.assertEqual(to_curl_args([], ""), ["-H", "Content-Type;"])
        self.assertEqual(to_curl_args([], "application/json"),
                         ["-H", "Content-Type: application/json"])


if __name__ == "__main__":
    unittest.main()
