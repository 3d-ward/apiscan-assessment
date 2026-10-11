"""Authentication providers.

EXTRACTED CAPABILITY (CAP-002): the source exercised named credential sets as
positive and negative identities (valid / wrong-role / invalid-credential).
That idea is preserved; the single hardcoded header scheme is generalised.

ENGINEERING IMPROVEMENT: bearer, basic and unauthenticated providers, and a
``purpose`` on every identity so a corpus can ask for "an identity that should
be refused" without knowing the engagement's naming.

Credential values arrive already resolved from the environment by the profile
loader. No provider reads a secret from disk, and no provider logs a value.
"""
import base64

from .errors import ProfileError


class AuthProvider(object):
    """Base provider. Subclasses turn an identity into request headers."""

    scheme = "none"

    def __init__(self, identities, default_identity):
        self.identities = identities
        self.default_identity = default_identity

    def headers_for(self, identity_name=None):
        raise NotImplementedError

    def purpose_of(self, identity_name=None):
        name = identity_name or self.default_identity
        return self.identities[name].get("purpose", "positive")

    def identities_with_purpose(self, purpose):
        return [n for n, v in sorted(self.identities.items())
                if v.get("purpose") == purpose]

    def _identity(self, identity_name):
        name = identity_name or self.default_identity
        if name not in self.identities:
            raise ProfileError("unknown identity %r (known: %s)"
                               % (name, ", ".join(sorted(self.identities))))
        return self.identities[name]


class NoAuth(AuthProvider):
    scheme = "none"

    def headers_for(self, identity_name=None):
        return {}


class HeaderTokenAuth(AuthProvider):
    """Arbitrary named headers per identity -- the most general scheme."""

    scheme = "header_token"

    def headers_for(self, identity_name=None):
        return dict(self._identity(identity_name).get("headers") or {})


class BearerAuth(AuthProvider):
    """``Authorization: Bearer <token>``; token supplied as headers.token."""

    scheme = "bearer"

    def headers_for(self, identity_name=None):
        ident = self._identity(identity_name)
        token = (ident.get("headers") or {}).get("token")
        if token is None:
            return {}
        return {"Authorization": "Bearer %s" % token}


class BasicAuth(AuthProvider):
    """HTTP Basic from headers.username / headers.password."""

    scheme = "basic"

    def headers_for(self, identity_name=None):
        ident = self._identity(identity_name)
        hdrs = ident.get("headers") or {}
        user, password = hdrs.get("username"), hdrs.get("password")
        if user is None and password is None:
            return {}
        blob = "%s:%s" % (user or "", password or "")
        encoded = base64.b64encode(blob.encode("utf-8")).decode("ascii")
        return {"Authorization": "Basic %s" % encoded}


_PROVIDERS = {
    "none": NoAuth,
    "header_token": HeaderTokenAuth,
    "bearer": BearerAuth,
    "basic": BasicAuth,
}


def from_profile(profile):
    """Build the provider a profile declares."""
    spec = profile.data["auth"]
    cls = _PROVIDERS.get(spec["provider"])
    if cls is None:
        raise ProfileError("unsupported auth provider %r (supported: %s)"
                           % (spec["provider"], ", ".join(sorted(_PROVIDERS))))
    return cls(spec["identities"], spec["default_identity"])
