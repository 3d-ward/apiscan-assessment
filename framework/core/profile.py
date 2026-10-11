"""Target profile loading, secret indirection and literal-secret refusal.

A profile describes an assessment surface: where it is, how to authenticate,
what endpoints exist, what a request body looks like and how to read a
response. It is the framework's only coupling point to a specific target --
no module anywhere else holds a target constant.

Credentials are never stored in a profile. They are referenced as
``${ENV:NAME}`` and resolved at load time from the process environment, which
an engagement populates from its own secret file. The loader actively refuses
a profile that contains what looks like a literal credential, because a
profile is a configuration artifact that tends to get committed and shared.
"""
import json
import os
import re
import math
import secrets
import uuid

from .errors import ProfileError, SecretInProfileError
from .schema import ValidationError, validate

SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "configs", "schemas", "target-profile.schema.json")

ENV_REF = re.compile(r"^\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}$")

# A key name that denotes a credential VALUE. Matched against the leaf key
# only -- an earlier version propagated "credential context" down from any
# ancestor named "auth", which flagged every description and role string under
# auth.identities as a secret. Context does not propagate here.
CREDENTIAL_KEY = re.compile(
    r"^(?:[\w-]*[-_])?(?:token|password|passwd|secret|apikey|api_key|"
    r"credential|passphrase|private_key|privatekey|client_secret)$"
    r"|^authorization$|^cookie$|^set-cookie$|^proxy-authorization$",
    re.I)

# JSON paths whose values are credentials by schema. Checked structurally so a
# credential cannot hide behind an unusual header name.
CREDENTIAL_LOCATIONS = (
    re.compile(r"^\$\.auth\.identities\.[^.]+\.headers\.[^.]+$"),
)

# Unconditional: these are never legitimate in a profile whatever the key.
HARD_SECRET_SHAPES = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PEM private key"),
    (re.compile(r"^(?:ey[A-Za-z0-9_-]{8,}\.){2}[A-Za-z0-9_-]+$"), "JWT"),
    (re.compile(r"^(?:AKIA|ASIA)[0-9A-Z]{16}$"), "AWS access key id"),
    (re.compile(r"^gh[pousr]_[A-Za-z0-9]{36,}$"), "GitHub token"),
    (re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"), "Slack token"),
)

MIN_SECRET_LENGTH = 20

# Shapes that are high-entropy but plainly not credentials.
URL_LIKE = re.compile(
    r"://"                                     # any scheme
    r"|^/"                                     # absolute path
    r"|^[A-Za-z]:[\\/]"                        # windows path
    r"|^[\w.-]+@[\w.-]+\.[A-Za-z]{2,}$"        # email
    r"|^[\w-]+(?:\.[\w-]+){2,}$"               # dotted hostname
)

# A kebab/snake identifier slug: lowercase words joined by - or _. Names like
# "example-callback-api" clear the entropy bar but are plainly not secrets,
# and issued credentials are essentially never word-delimited this way.
SLUG_LIKE = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)+$")


def _entropy(value):
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    total = 0.0
    for c in counts.values():
        p = c / n
        total -= p * math.log(p, 2)
    return total


def _high_entropy_secret(value):
    """True when *value* looks like real credential material.

    Length alone is not enough. Three classes of legitimate profile content
    otherwise trip a naive length-plus-entropy test, and all three appear in
    the framework's own example profile:

      * a repeated-character placeholder (64 zeros as a template seed)
      * a pure-hexadecimal value -- identifier *structure*, not a secret
      * a URL, host or filesystem path -- high entropy, obviously not a secret
      * a kebab-case name such as a profile or endpoint identifier

    These are excluded here. Credentials hiding in those shapes are still
    caught by the structural location check and the key-name check, which do
    not depend on entropy at all -- so narrowing this heuristic trades false
    positives away without creating a blind spot.
    """
    if len(value) < MIN_SECRET_LENGTH:
        return None
    if re.match(r"^(.)\1*$", value):
        return None                       # single repeated character
    if re.match(r"^[0-9a-fA-F]+$", value):
        return None                       # pure hex: identifier structure
    if URL_LIKE.search(value):
        return None                       # url, host, path or email
    if SLUG_LIKE.match(value):
        return None                       # kebab/snake identifier slug
    classes = sum([
        bool(re.search(r"[a-z]", value)),
        bool(re.search(r"[A-Z]", value)),
        bool(re.search(r"\d", value)),
        bool(re.search(r"[^A-Za-z0-9]", value)),
    ])
    if classes < 2:
        return None
    if not re.match(r"^[A-Za-z0-9+/=_.:-]+$", value):
        return None                       # prose, not an opaque token
    if " " in value:
        return None
    ent = _entropy(value)
    if ent < 3.2:
        return None
    return "high-entropy opaque value (%.1f bits/char, %d chars)" % (ent, len(value))


def _hard_secret(value):
    for rx, label in HARD_SECRET_SHAPES:
        if rx.search(value):
            return label
    return None


class Profile(object):
    """A validated, secret-resolved target profile."""

    def __init__(self, data, source_path=None, resolved_env=None):
        self.data = data
        self.source_path = source_path
        self.resolved_env = resolved_env or {}

    # -- accessors -------------------------------------------------------
    @property
    def name(self):
        return self.data["identity"]["name"]

    @property
    def transport(self):
        return self.data["transport"]

    @property
    def base_url(self):
        return self.data["transport"]["base_url"].rstrip("/")

    @property
    def proxy(self):
        return self.data["transport"].get("proxy") or None

    @property
    def response_model(self):
        return self.data["response_model"]

    @property
    def envelope(self):
        return self.data["response_model"].get("envelope") or None

    @property
    def endpoints(self):
        return {e["id"]: e for e in self.data["endpoints"]}

    @property
    def endpoint_ids(self):
        return [e["id"] for e in self.data["endpoints"]]

    @property
    def identities(self):
        return self.data["auth"]["identities"]

    @property
    def default_identity(self):
        return self.data["auth"]["default_identity"]

    def endpoint(self, endpoint_id):
        try:
            return self.endpoints[endpoint_id]
        except KeyError:
            raise ProfileError("unknown endpoint %r (known: %s)"
                               % (endpoint_id, ", ".join(self.endpoint_ids)))

    def url_for(self, endpoint_id):
        return self.base_url + self.endpoint(endpoint_id)["path"]

    def template_for(self, endpoint_id):
        ep = self.endpoint(endpoint_id)
        tname = ep.get("payload_template") or "default"
        tpls = self.data["payload_templates"]
        if tname not in tpls:
            raise ProfileError("endpoint %r references unknown payload template %r"
                               % (endpoint_id, tname))
        return tpls[tname]

    def identity(self, name):
        if name not in self.identities:
            raise ProfileError("unknown identity %r (known: %s)"
                               % (name, ", ".join(sorted(self.identities))))
        return self.identities[name]

    def generate_identifier(self, space_name):
        """Produce a synthetic identifier for an identifier space."""
        spaces = self.data.get("identifier_spaces") or {}
        if space_name not in spaces:
            raise ProfileError("unknown identifier space %r" % space_name)
        spec = spaces[space_name]["generator"]
        if spec == "uuid4":
            return str(uuid.uuid4())
        if spec.startswith("hex:"):
            nbytes = max(1, int(spec.split(":", 1)[1]) // 2)
            return secrets.token_hex(nbytes)
        if spec.startswith("literal:"):
            return spec.split(":", 1)[1]
        if spec.startswith("pattern:"):
            # Expand a tiny template: # -> digit, @ -> uppercase letter.
            out = []
            for ch in spec.split(":", 1)[1]:
                if ch == "#":
                    out.append(secrets.choice("0123456789"))
                elif ch == "@":
                    out.append(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
                else:
                    out.append(ch)
            return "".join(out)
        raise ProfileError("unsupported identifier generator %r" % spec)

    def identifier_for(self, endpoint_id):
        ep = self.endpoint(endpoint_id)
        space = ep.get("identifier_space")
        if not space:
            raise ProfileError("endpoint %r declares no identifier_space" % endpoint_id)
        return self.generate_identifier(space)


# -- secret handling -----------------------------------------------------
def scan_for_literal_secrets(data, path="$"):
    """Return a list of (json_path, reason) for literal credentials found.

    Three independent checks, deliberately ordered cheapest-first:

      1. structural -- a value sitting where the schema says a credential goes
      2. key name   -- a leaf key that denotes a credential value
      3. value shape -- hard-coded secret formats, then entropy

    A value that is an ``${ENV:NAME}`` reference always passes.
    """
    problems = []

    def check_leaf(value, p, key):
        if not isinstance(value, str) or not value or ENV_REF.match(value):
            return
        hard = _hard_secret(value)
        if hard:
            problems.append((p, "value is a %s" % hard))
            return
        if any(rx.match(p) for rx in CREDENTIAL_LOCATIONS):
            problems.append((p, "credential location requires an ${ENV:NAME} "
                                "reference, found a literal"))
            return
        if key and CREDENTIAL_KEY.match(str(key)):
            problems.append((p, "key %r denotes a credential; use ${ENV:NAME}"
                             % key))
            return
        shape = _high_entropy_secret(value)
        if shape:
            problems.append((p, "value resembles a secret: %s" % shape))

    def walk(node, p, key):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, "%s.%s" % (p, k), k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, "%s[%d]" % (p, i), key)
        else:
            check_leaf(node, p, key)

    walk(data, path, None)
    return problems


def resolve_env_refs(data, env=None, strict=True):
    """Replace every ``${ENV:NAME}`` with its environment value.

    Returns (resolved_copy, resolved_names). With *strict*, a missing variable
    is an error -- running an assessment with a silently empty credential
    produces authentication findings that are artifacts of the harness.
    """
    env = os.environ if env is None else env
    seen = {}
    missing = []

    def walk(node):
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, str):
            m = ENV_REF.match(node)
            if m:
                name = m.group(1)
                if name not in env or env[name] == "":
                    missing.append(name)
                    return node
                seen[name] = True
                return env[name]
        return node

    out = walk(data)
    if missing and strict:
        raise ProfileError(
            "unresolved secret reference(s): %s. Populate the engagement secret "
            "file and export them before running."
            % ", ".join(sorted(set(missing))))
    return out, sorted(seen)


def load_schema(path=None):
    with open(path or SCHEMA_PATH) as fh:
        return json.load(fh)


def load(path, env=None, strict_env=True, allow_literal_secrets=False):
    """Load, validate and resolve a target profile from *path*."""
    try:
        with open(path) as fh:
            raw = json.load(fh)
    except (IOError, OSError) as exc:
        raise ProfileError("cannot read profile %s: %s" % (path, exc))
    except ValueError as exc:
        raise ProfileError("profile %s is not valid JSON: %s" % (path, exc))
    return load_data(raw, source_path=path, env=env, strict_env=strict_env,
                     allow_literal_secrets=allow_literal_secrets)


def load_data(raw, source_path=None, env=None, strict_env=True,
              allow_literal_secrets=False):
    """Validate and resolve an already-parsed profile mapping."""
    try:
        validate(raw, load_schema())
    except ValidationError as exc:
        raise ProfileError("profile %s failed validation:\n%s"
                           % (source_path or "<inline>", exc))

    if not allow_literal_secrets:
        problems = scan_for_literal_secrets(raw)
        if problems:
            raise SecretInProfileError(
                "profile %s contains %d literal secret(s); use ${ENV:NAME} "
                "instead:\n  %s"
                % (source_path or "<inline>", len(problems),
                   "\n  ".join("%s -- %s" % p for p in problems)))

    # Cross-reference checks the schema cannot express.
    ids = [e["id"] for e in raw["endpoints"]]
    if len(ids) != len(set(ids)):
        raise ProfileError("duplicate endpoint id(s) in profile")
    if raw["auth"]["default_identity"] not in raw["auth"]["identities"]:
        raise ProfileError("default_identity %r is not defined in auth.identities"
                           % raw["auth"]["default_identity"])
    spaces = set((raw.get("identifier_spaces") or {}))
    for ep in raw["endpoints"]:
        sp = ep.get("identifier_space")
        if sp and sp not in spaces:
            raise ProfileError("endpoint %r references unknown identifier_space %r"
                               % (ep["id"], sp))
        tpl = ep.get("payload_template")
        if tpl and tpl not in raw["payload_templates"]:
            raise ProfileError("endpoint %r references unknown payload_template %r"
                               % (ep["id"], tpl))

    resolved, names = resolve_env_refs(raw, env=env, strict=strict_env)
    return Profile(resolved, source_path=source_path, resolved_env=names)
