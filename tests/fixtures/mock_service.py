"""A deliberately imperfect API, on loopback, for integration testing.

Binds to 127.0.0.1 on an ephemeral port. Performs no outbound connection and
resolves no names, so the framework's integration tests never leave the host.

The service is written to be *wrong in specific, controlled ways*, because a
test target that behaves perfectly cannot prove a scanner detects anything:

  * it answers HTTP 200 with an application envelope for both acceptance and
    refusal, which is what forces layer attribution to read the body
  * it leaks a SQL error for one particular input
  * it reflects the identifier verbatim for another
  * it accepts undeclared properties (mass assignment)
  * its uniqueness check on the correlation identifier is case-sensitive
  * it enforces a body-size limit, and a media-type check, correctly

Toggle ``strict`` to make it behave well, which is how the suite checks the
scanner does not invent findings against a clean target.
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ENDPOINTS = {
    "/v1/notify/created": "resource_create",
    "/v1/notify/updated": "resource_update",
    "/v1/notify/audit-entry": "audit_entry",
    "/v1/notify/declaration": "declaration",
}

VALID_ID = "synth-primary"
VALID_TOKEN = "synthtok1"
WRONGROLE_ID = "synth-wrongrole"
WRONGROLE_TOKEN = "synthtok2"

MAX_BODY = 16384

#: In strict mode the service validates that the identifier belongs to the
#: namespace the endpoint owns. A hardened API knows the shape of its own
#: identifiers; without this the fixture cannot represent one.
NAMESPACE_PATTERNS = {
    "resource_create": r"^SYNTH-[A-Z]{2}\d{7}$",
    "resource_update": r"^SYNTH-[A-Z]{2}\d{7}$",
    "audit_entry": r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "declaration": r"^SYNTH-DEC-\d{8}$",
}

#: Characters that have no business in an opaque business identifier.
UNSAFE_IDENTIFIER = re.compile(r"""[<>'"`;$#{}\\\x00-\x1f]|\.\.|%2f|%3c""", re.I)

ALLOWED_FIELDS = {"message", "success", "correlationId"}
ALLOWED_MESSAGE_FIELDS = {"key", "error", "note"}


class State(object):
    def __init__(self):
        self.consumed = set()
        self.strict = False
        self.requests = 0
        self.lock = threading.Lock()

    def reset(self):
        with self.lock:
            self.consumed = set()
            self.requests = 0


STATE = State()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass                                  # silence test output

    # -- helpers ---------------------------------------------------------
    def _send(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode("utf-8") \
            if not isinstance(payload, bytes) else payload
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _envelope(self, code, message, errors=None):
        return {"resultCode": code, "resultMessage": message,
                "errors": errors}

    def _all_headers(self, name):
        return self.headers.get_all(name) or []

    def _auth(self):
        """Return (ok, envelope_or_None)."""
        ids = self._all_headers("x-client-id")
        tokens = self._all_headers("x-client-token")
        if not ids or not tokens:
            return False, self._envelope("0401", "Authentication required")
        if STATE.strict and len(ids) > 1:
            return False, self._envelope(
                "0401", "Duplicate credential headers are rejected")
        if len(tokens) > 1:
            # Deliberate defect: picks the LAST value, so an invalid credential
            # followed by a valid one authenticates.
            if not STATE.strict:
                tokens = [tokens[-1]]
            else:
                return False, self._envelope(
                    "0401", "Duplicate credential headers are rejected")
        cid, token = ids[0].strip(), tokens[0].strip()
        if not cid or not token:
            return False, self._envelope("0401", "Authentication required")
        if (cid, token) == (VALID_ID, VALID_TOKEN):
            return True, None
        if (cid, token) == (WRONGROLE_ID, WRONGROLE_TOKEN):
            return False, self._envelope("0403", "Role not permitted")
        return False, self._envelope("0401", "Authentication failed")

    # -- request handling ------------------------------------------------
    def _handle(self, method):
        with STATE.lock:
            STATE.requests += 1

        path = self.path.split("?")[0]
        if path not in ENDPOINTS:
            self._send(404, self._envelope("0404", "No such route"))
            return

        if method != "POST":
            self._send(405, self._envelope("0405",
                                           "Method %s is not supported" % method),
                       {"Allow": "POST"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self.rfile.read(min(length, MAX_BODY))
            self._send(413, self._envelope("0413", "Request body too large"))
            return
        raw = self.rfile.read(length) if length else b""

        ctype_raw = (self.headers.get("Content-Type") or "").strip()
        ctype = ctype_raw.split(";")[0].strip()
        if ctype != "application/json":
            self._send(415, self._envelope(
                "0415", "Unsupported media type %r" % (ctype or "(absent)")))
            return
        if STATE.strict and ";" in ctype_raw:
            params = ctype_raw.split(";", 1)[1].strip().lower()
            if params and params not in ("charset=utf-8",):
                self._send(415, self._envelope(
                    "0415", "Unsupported media-type parameter %r" % params))
                return

        ok, failure = self._auth()
        if not ok:
            status = 403 if failure["resultCode"] == "0403" else 401
            self._send(status, failure)
            return

        text = raw.decode("utf-8", "replace")
        try:
            doc = json.loads(text)
        except ValueError:
            self._send(400, self._envelope("0400", "Malformed JSON body"))
            return

        if not isinstance(doc, dict):
            self._send(400, self._envelope("0400",
                                           "Body must be a JSON object"))
            return

        message = doc.get("message")
        if not isinstance(message, dict):
            self._send(400, self._envelope("0400",
                                           "Field 'message' is required"))
            return
        key = message.get("key")
        corr = doc.get("correlationId")

        # Deliberate defect: a SQL error leaks for a specific input shape.
        if isinstance(key, str) and "UNION SELECT" in key.upper() \
                and not STATE.strict:
            self._send(200, self._envelope(
                "0500",
                "ERROR: syntax error at or near \"UNION\" at character 42"))
            return

        # Deliberate defect: verbatim reflection of a template vector.
        if isinstance(key, str) and key.startswith("${") and not STATE.strict:
            self._send(200, self._envelope("0400",
                                           "Rejected value: %s" % key))
            return

        if not isinstance(key, str) or not key.strip():
            self._send(400, self._envelope(
                "0400", "Field 'message.key' must be a non-empty string"))
            return

        if not isinstance(corr, str) or not re.match(r"^[0-9a-fA-F]{64}$",
                                                     corr or ""):
            self._send(400, self._envelope(
                "0400", "Field 'correlationId' must be 64 hexadecimal "
                        "characters"))
            return

        if "success" in doc and not isinstance(doc["success"], bool):
            self._send(400, self._envelope(
                "0400", "Field 'success' must be a boolean"))
            return

        endpoint = ENDPOINTS[path]

        if STATE.strict:
            # Contradictory status in either direction.
            if doc.get("success") is True and message.get("error"):
                self._send(400, self._envelope(
                    "0400",
                    "Contradictory status: success with an error present"))
                return
            if doc.get("success") is False and not message.get("error"):
                self._send(400, self._envelope(
                    "0400",
                    "A failure status must be accompanied by an error"))
                return
            # Every declared field is mandatory.
            missing = ALLOWED_FIELDS - set(doc)
            if missing:
                self._send(400, self._envelope(
                    "0400", "Missing required field(s): %s"
                            % ", ".join(sorted(missing))))
                return
            unknown_msg = set(message) - ALLOWED_MESSAGE_FIELDS
            if unknown_msg:
                self._send(400, self._envelope(
                    "0400", "Unknown field(s) in message: %s"
                            % ", ".join(sorted(unknown_msg))))
                return
            # The identifier must belong to this endpoint's namespace.
            pattern = NAMESPACE_PATTERNS.get(endpoint)
            if pattern and not re.match(pattern, key):
                self._send(400, self._envelope(
                    "0400", "Identifier does not belong to the namespace this "
                            "endpoint owns"))
                return
            if UNSAFE_IDENTIFIER.search(key):
                self._send(400, self._envelope(
                    "0400", "Identifier contains characters that are not "
                            "permitted"))
                return
            # Correlation identifiers are lowercase hex and distinct from the
            # resource identifier.
            if corr != corr.lower():
                self._send(400, self._envelope(
                    "0400", "correlationId must be lowercase hexadecimal"))
                return
            if corr == key:
                self._send(400, self._envelope(
                    "0400", "correlationId must not equal message.key"))
                return
            for field in ("error", "note"):
                value = message.get(field)
                if value is not None and not isinstance(value, str):
                    self._send(400, self._envelope(
                        "0400", "Field 'message.%s' must be a string or null"
                                % field))
                    return
                if isinstance(value, str) and UNSAFE_IDENTIFIER.search(value):
                    self._send(400, self._envelope(
                        "0400", "Field 'message.%s' contains characters that "
                                "are not permitted" % field))
                    return

        # Deliberate defect: undeclared properties are accepted silently.
        undeclared = [k for k in doc
                      if k not in ("message", "success", "correlationId")]
        if undeclared and STATE.strict:
            self._send(400, self._envelope(
                "0400", "Unknown properties: %s" % ", ".join(sorted(undeclared))))
            return

        # Uniqueness on the correlation identifier -- case-sensitive by
        # default, which is the whole point of the case_sensitivity probe.
        marker = corr if not STATE.strict else corr.lower()
        with STATE.lock:
            if marker in STATE.consumed:
                self._send(409, self._envelope(
                    "0409", "Correlation identifier has already been processed"))
                return
            STATE.consumed.add(marker)

        self._send(200, self._envelope("0000", "Success"))

    def do_POST(self):
        self._handle("POST")

    def do_GET(self):
        self._handle("GET")

    def do_PUT(self):
        self._handle("PUT")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_PATCH(self):
        self._handle("PATCH")

    def do_OPTIONS(self):
        self._handle("OPTIONS")

    def do_HEAD(self):
        self._handle("HEAD")

    def do_TRACE(self):
        self._handle("TRACE")


class MockService(object):
    """Context manager yielding a base URL on loopback."""

    def __init__(self, strict=False):
        self.strict = strict
        self.server = None
        self.thread = None

    def __enter__(self):
        STATE.reset()
        STATE.strict = self.strict
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        return self

    @property
    def base_url(self):
        host, port = self.server.server_address[:2]
        return "http://%s:%d/v1" % (host, port)

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        return False


def _serve_forever(port=0, strict=False):
    """Run the mock standalone: ``python3 mock_service.py [port] [strict]``."""
    STATE.reset()
    STATE.strict = strict
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    host, bound = server.server_address[:2]
    print("mock service on http://%s:%d/v1 (strict=%s)" % (host, bound, strict),
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    import sys as _sys
    _port = int(_sys.argv[1]) if len(_sys.argv) > 1 else 0
    _strict = len(_sys.argv) > 2 and _sys.argv[2] == "strict"
    _serve_forever(_port, _strict)
