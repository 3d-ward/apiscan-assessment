"""Response security-header assessment.

EXTRACTED CAPABILITY (part of CAP-029). Observes one well-formed response and
reports which security headers are absent and which discouraged headers
advertise the stack. Observation only -- it sends a single valid request.
"""
from ..corpus.generators.followup import assess_response_headers
from ..methodology import taxonomy as TX


def assess(headers_text):
    """Evaluate a header block. Returns a module result with findings."""
    result = assess_response_headers(headers_text)
    findings = []
    for item in result["missing"]:
        findings.append({
            "title": "Security response header %s is absent" % item["header"],
            "severity": item["severity"],
            "cwe": "CWE-693: Protection Mechanism Failure",
            "detail": item["why"],
            "recommendation": "Set %s on API responses." % item["header"],
        })
    for item in result["advertised"]:
        findings.append({
            "title": "Response header %s discloses component detail"
                     % item["header"],
            "severity": item["severity"],
            "cwe": "CWE-200: Exposure of Sensitive Information",
            "detail": "%s (observed value: %r)" % (item["why"], item["value"]),
            "recommendation": "Suppress or genericise the %s header."
                              % item["header"],
        })
    return {
        "module": "response_headers",
        "status": "OBSERVED",
        "present_count": len(result["present"]),
        "missing": result["missing"],
        "advertised": result["advertised"],
        "findings": findings,
        "note": ("Header presence is a configuration observation. Several of "
                 "these headers matter less to a pure JSON API than to a "
                 "browser-rendered application; severity should be adjusted to "
                 "the consumer, which is why they are reported individually "
                 "rather than as a single composite finding."),
        "expected_set": [h[0] for h in TX.EXPECTED_SECURITY_HEADERS],
    }
