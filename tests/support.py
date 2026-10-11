"""Shared test helpers. Standard library only."""
import copy
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

EXAMPLE_PROFILE = os.path.join(ROOT, "configs", "examples",
                               "example-callback-api.json")

#: Synthetic credentials for the example profile. These are fabricated values
#: for a loopback mock; they authenticate against nothing real.
TEST_ENV = {
    "EXAMPLE_PRIMARY_ID": "synth-primary",
    "EXAMPLE_PRIMARY_TOKEN": "synthtok1",
    "EXAMPLE_WRONGROLE_ID": "synth-wrongrole",
    "EXAMPLE_WRONGROLE_TOKEN": "synthtok2",
    "EXAMPLE_BADTOKEN_ID": "synth-badtoken",
    "EXAMPLE_BADTOKEN_TOKEN": "synthtok-invalid",
}


def raw_profile():
    with open(EXAMPLE_PROFILE) as fh:
        return json.load(fh)


def load_profile(base_url=None, proxy=None, env=None):
    from framework.core import profile as P
    data = copy.deepcopy(raw_profile())
    # Fixtures stand in for a CONFIGURED engagement, not the scaffold. The
    # preflight placeholder check exists precisely to catch a profile still
    # describing the example, so leaving these at their example values would
    # make every fixture trip it.
    data["identity"] = dict(data["identity"],
                            name="fixture-target",
                            description="Configured fixture target.",
                            engagement_ref="FIXTURE-0001")
    if base_url is not None:
        data["transport"]["base_url"] = base_url
    data["transport"]["proxy"] = proxy
    # `env or TEST_ENV` would be wrong: an intentionally EMPTY env
    # is falsy and would silently fall back to the defaults, making
    # a missing-credential test pass for the wrong reason.
    return P.load_data(data, env=dict(TEST_ENV if env is None else env))


def auth_for(profile):
    from framework.core import auth as A
    return A.from_profile(profile)


class FakeResponse(object):
    """A Response-shaped object for oracle tests, with no I/O."""

    def __init__(self, status, body="", headers="", meta=None):
        self.status = str(status)
        self.body = body
        self.headers = headers
        self.meta = meta or {}

    @property
    def ok_transport(self):
        return self.status not in ("000", "", None)

    @property
    def status_int(self):
        try:
            return int(self.status)
        except (TypeError, ValueError):
            return 0

    def header(self, name):
        want = name.lower()
        for line in (self.headers or "").splitlines():
            if ":" in line and line.split(":", 1)[0].strip().lower() == want:
                return line.split(":", 1)[1].strip()
        return None
