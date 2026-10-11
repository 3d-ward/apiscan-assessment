"""Transport-layer posture assessment.

EXTRACTED CAPABILITY (CAP-026).

Everything here happens below HTTP, which has two consequences the source
learned the hard way and this module encodes:

1. **These checks cannot run through an intercepting proxy.** A proxy
   terminates TLS and performs its own upstream handshake, presenting whatever
   client certificate it has been configured with. A "no client certificate"
   test sent through a proxy therefore silently acquires one and the finding
   stops reproducing. Every function here runs DIRECT, and the evidence is
   stamped ``CaptureMethod.DIRECT`` so a report cannot claim otherwise.

2. **Distinct rejection messages are themselves a finding.** If a server
   answers differently for "no certificate" and "untrusted certificate", it is
   validating the issuing chain rather than merely checking presence -- which
   is a positive control worth recording -- but it also lets an unauthenticated
   caller distinguish the two states.

``openssl`` is the baseline. ``nmap`` and ``testssl.sh`` enrich the result when
present; when they are absent the relevant sections are reported NOT VERIFIED
rather than silently omitted.
"""
import re
import shutil
import subprocess

from ..core.errors import AuthorisationError
from ..evidence.provenance import CaptureMethod
from ..governance.scope import TransportProbe

NOT_VERIFIED = "NOT VERIFIED"


def _gate(probe_id, scope_policy, endpoint=None):
    """Refuse to open a socket that the engagement has not authorised.

    Every function in this module that touches the network calls this first.
    A missing policy is a refusal, not a default-allow: this module is the one
    that talks to the client's edge, and "nobody passed a policy" must never be
    the reason a packet went out.
    """
    if scope_policy is None:
        raise AuthorisationError(
            "transport probe %r refused: no scope policy was supplied. This "
            "module opens sockets to the target, so it is gated like any "
            "corpus case. Pass scope_policy=ScopePolicy.load(<engagement "
            "scope-policy.json>). Probes carry the class 'transport_probe', "
            "and because transport evidence must be captured direct they also "
            "need an authorisation for 'direct_transport' when the policy "
            "sets require_proxy." % probe_id)
    scope_policy.require(TransportProbe(probe_id, endpoint=endpoint))
    return True


def _run(cmd, timeout=45, stdin_data=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, errors="replace",
                              input=stdin_data)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except OSError as exc:
        return 127, "", str(exc)


def tool_availability():
    return {
        "openssl": shutil.which("openssl"),
        "nmap": shutil.which("nmap"),
        "testssl": shutil.which("testssl.sh") or shutil.which("testssl"),
    }


# -- certificate revocation ---------------------------------------------
def certificate_revocation(cert_path):
    """Can this certificate actually be revoked?

    A PKI with no CRL distribution point and no OCSP responder has nothing to
    withdraw per-certificate: trust is anchored at the CA and the only
    remediation for a compromised client certificate is to re-issue the whole
    trust chain. That is the finding, and it is visible from the certificate
    alone.
    """
    tools = tool_availability()
    if not tools["openssl"]:
        return {"module": "tls_posture.certificate_revocation",
                "status": NOT_VERIFIED,
                "reason": "openssl is not available",
                "capture_method": CaptureMethod.DIRECT}
    rc, out, err = _run(["openssl", "x509", "-in", cert_path, "-noout",
                         "-text"])
    if rc != 0:
        return {"module": "tls_posture.certificate_revocation",
                "status": NOT_VERIFIED,
                "reason": "could not read certificate: %s" % (err.strip()[:160]),
                "capture_method": CaptureMethod.DIRECT}

    has_crl = "X509v3 CRL Distribution Points" in out
    has_ocsp = "OCSP - URI" in out or "OCSP;URI" in out
    has_aia = "Authority Information Access" in out

    rc2, meta, _ = _run(["openssl", "x509", "-in", cert_path, "-noout",
                         "-serial", "-subject", "-issuer", "-enddate",
                         "-fingerprint", "-sha256"])
    revocable = has_crl or has_ocsp
    return {
        "module": "tls_posture.certificate_revocation",
        "status": "OBSERVED",
        "capture_method": CaptureMethod.DIRECT,
        "crl_distribution_point": has_crl,
        "ocsp_responder": has_ocsp,
        "authority_information_access": has_aia,
        "revocation_possible": revocable,
        "certificate_metadata": " ".join(meta.split()),
        "finding": None if revocable else {
            "title": "Client certificate carries no revocation mechanism",
            "severity": "Medium",
            "cwe": "CWE-299: Improper Check for Certificate Revocation",
            "detail": ("The certificate presents neither a CRL distribution "
                       "point nor an OCSP responder URI, so there is no "
                       "per-certificate mechanism to withdraw trust. A "
                       "compromised key cannot be revoked without re-issuing "
                       "the trust anchor or maintaining a gateway-level "
                       "denylist by serial or fingerprint."),
            "recommendation": ("Issue certificates with a reachable CRL "
                               "distribution point or OCSP responder, or "
                               "implement gateway-level blocking by serial "
                               "number or fingerprint and document the "
                               "revocation process."),
        },
    }


# -- negotiated protocol and cipher -------------------------------------
def negotiated_parameters(host, port=443, servername=None,
                          scope_policy=None, endpoint=None):
    """What the server actually negotiates with a default client."""
    _gate("tls.negotiated_parameters", scope_policy, endpoint)
    tools = tool_availability()
    if not tools["openssl"]:
        return {"module": "tls_posture.negotiated_parameters",
                "status": NOT_VERIFIED, "reason": "openssl is not available",
                "capture_method": CaptureMethod.DIRECT}
    sni = servername or host
    rc, out, err = _run(
        ["openssl", "s_client", "-connect", "%s:%d" % (host, port),
         "-servername", sni, "-brief"], stdin_data="")
    blob = out + err
    proto = re.search(r"Protocol version:\s*(\S+)", blob)
    cipher = re.search(r"Ciphersuite:\s*(\S+)", blob)
    peer = re.search(r"Peer certificate:\s*(.+)", blob)
    ca_names = re.findall(r"Acceptable client certificate CA names\s*(.*)",
                          blob, re.S)
    return {
        "module": "tls_posture.negotiated_parameters",
        "status": "OBSERVED" if proto else NOT_VERIFIED,
        "capture_method": CaptureMethod.DIRECT,
        "host": host, "port": port,
        "protocol": proto.group(1) if proto else None,
        "ciphersuite": cipher.group(1) if cipher else None,
        "peer_certificate": peer.group(1).strip() if peer else None,
        "client_ca_names_advertised": bool(ca_names),
        "note": ("Captured DIRECT. These parameters cannot be observed through "
                 "an intercepting proxy, which terminates TLS and would report "
                 "its own negotiated session instead."),
        "finding": ({
            "title": "Internal PKI naming disclosed in the TLS "
                     "CertificateRequest",
            "severity": "Informational",
            "cwe": "CWE-200: Exposure of Sensitive Information",
            "detail": ("The server advertises acceptable client-certificate CA "
                       "names during the handshake. This is standard TLS "
                       "behaviour and not a vulnerability on its own, but it "
                       "discloses internal certificate-authority naming to any "
                       "unauthenticated party able to open a socket."),
            "recommendation": "Note only; no remediation is normally expected.",
        } if ca_names else None),
    }


def cipher_enumeration(host, port=443, scope_policy=None, endpoint=None):
    """Enumerate accepted ciphers. Requires nmap or testssl.sh."""
    _gate("tls.cipher_enumeration", scope_policy, endpoint)
    tools = tool_availability()
    if tools["nmap"]:
        rc, out, err = _run(["nmap", "--script", "ssl-enum-ciphers", "-p",
                             str(port), host], timeout=180)
        if rc == 0:
            return {"module": "tls_posture.cipher_enumeration",
                    "status": "OBSERVED", "tool": "nmap",
                    "capture_method": CaptureMethod.DIRECT, "output": out}
        return {"module": "tls_posture.cipher_enumeration",
                "status": NOT_VERIFIED, "tool": "nmap",
                "reason": err.strip()[:200],
                "capture_method": CaptureMethod.DIRECT}
    if tools["testssl"]:
        rc, out, err = _run([tools["testssl"], "--quiet", "--color", "0",
                             "%s:%d" % (host, port)], timeout=600)
        return {"module": "tls_posture.cipher_enumeration",
                "status": "OBSERVED" if rc == 0 else NOT_VERIFIED,
                "tool": "testssl.sh", "output": out,
                "capture_method": CaptureMethod.DIRECT}
    return {
        "module": "tls_posture.cipher_enumeration",
        "status": NOT_VERIFIED,
        "reason": ("neither nmap nor testssl.sh is available; cipher "
                   "enumeration was not performed and must be reported as not "
                   "established rather than as a clean result"),
        "remedy": "install nmap (--script ssl-enum-ciphers) or testssl.sh",
        "capture_method": CaptureMethod.DIRECT,
    }


# -- client-certificate enforcement --------------------------------------
def client_cert_enforcement(url, cert_path=None, key_path=None,
                            untrusted_cert=None, untrusted_key=None,
                            timeout=30, scope_policy=None, endpoint=None):
    """Probe mutual-TLS enforcement with no certificate and an untrusted one.

    Runs DIRECT by necessity. Differing responses between the two probes are
    evidence that the issuing chain is validated rather than merely checked for
    presence -- a positive control -- while also constituting a minor state
    enumeration.
    """
    _gate("tls.client_cert_enforcement", scope_policy, endpoint)
    def probe(args, label):
        cmd = ["curl", "-sS", "-k", "-o", "-", "-w", "<<%{http_code}>>",
               "--max-time", str(timeout)] + args + [url]
        rc, out, err = _run(cmd, timeout=timeout + 10)
        m = re.search(r"<<(\d{3})>>", out or "")
        return {"label": label, "status": m.group(1) if m else "000",
                "body": re.sub(r"<<\d{3}>>", "", out or "")[:600],
                "stderr": err.strip()[:300], "curl_rc": rc}

    results = [probe([], "no client certificate")]
    if untrusted_cert and untrusted_key:
        results.append(probe(["--cert", untrusted_cert, "--key", untrusted_key],
                             "untrusted (self-signed) client certificate"))
    if cert_path and key_path:
        results.append(probe(["--cert", cert_path, "--key", key_path],
                             "issued client certificate"))

    messages = [(r["label"], r["status"], r["body"][:200]) for r in results]
    distinct = len({r["body"][:120] for r in results[:2]}) > 1 \
        if len(results) >= 2 else None

    out = {
        "module": "tls_posture.client_cert_enforcement",
        "status": "OBSERVED",
        "capture_method": CaptureMethod.DIRECT,
        "url": url,
        "probes": results,
        "message_summary": messages,
        "chain_validated": distinct,
        "note": ("Captured DIRECT. An intercepting proxy would attach its own "
                 "configured client certificate, so the 'no certificate' probe "
                 "would not reproduce and the application would be reached "
                 "instead."),
        "findings": [],
    }
    if distinct:
        out["findings"].append({
            "title": "Distinct TLS rejection messages permit state enumeration",
            "severity": "Informational",
            "cwe": "CWE-204: Observable Response Discrepancy",
            "detail": ("The server returns different messages for a missing "
                       "certificate and an untrusted certificate, letting an "
                       "unauthenticated caller distinguish the two states. The "
                       "same difference is positive evidence that the issuing "
                       "chain is validated, not merely that a certificate was "
                       "presented."),
            "recommendation": ("Return a single generic rejection for all "
                               "client-certificate failures."),
        })
    return out
