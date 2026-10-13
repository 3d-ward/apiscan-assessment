"""The test plan: what a live run would do, stated before it does it.

ENGINEERING IMPROVEMENT (review finding: "before execution, show the actual
destination, endpoints, identities, request count, and potentially
data-changing operations").

The framework could already describe a corpus -- ``generate`` printed counts
by family and phase. What it could not do was answer the question an operator
or a client actually asks before authorising a run:

    Which host is this going to hit, as whom, how many times, and what might
    it change?

Counts by payload family do not answer that. A plan does, and it is built from
the same corpus and the same policy the run will use, so it cannot describe a
different run from the one that executes. ``apiscan plan`` writes it as a
reviewable artifact; ``scan`` prints it and, on a terminal, requires the
operator to confirm it.

Nothing here resolves a credential value. Identities are listed by name and
purpose, because the plan is a document that gets pasted into an e-mail asking
for approval.
"""
from urllib.parse import urlparse


def build(profile, cases, policy, mode=None, limits=None, via_proxy=None,
          today=None):
    """Assemble the plan. Sends nothing and resolves no secret."""
    permitted, denied = policy.filter(list(cases), today, via_proxy=via_proxy)
    parsed = urlparse(profile.base_url or "")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    mutating = [c for c in permitted if getattr(c, "state_mutating", True)]
    by_endpoint = {}
    for case in permitted:
        by_endpoint.setdefault(case.endpoint, []).append(case)

    endpoints = []
    for endpoint_id in profile.endpoint_ids:
        spec = profile.endpoint(endpoint_id) or {}
        rows = by_endpoint.get(endpoint_id, [])
        endpoints.append({
            "id": endpoint_id,
            "path": spec.get("path", ""),
            "url": profile.url_for(endpoint_id),
            "methods": sorted({c.method for c in rows}) or list(
                spec.get("methods") or []),
            "cases_to_send": len(rows),
            "data_changing_cases": sum(
                1 for c in rows if getattr(c, "state_mutating", True)),
        })

    identities = []
    for name, spec in sorted((profile.identities or {}).items()):
        identities.append({
            "name": name,
            "purpose": spec.get("purpose", ""),
            "credential_source": "${ENV:...} resolved at load time; no value "
                                 "appears in this plan",
        })

    denial_reasons = {}
    for case, reason in denied:
        denial_reasons[reason] = denial_reasons.get(reason, 0) + 1

    payload_classes = {}
    for case in permitted:
        key = getattr(case, "payload_class", "benign")
        payload_classes[key] = payload_classes.get(key, 0) + 1

    tls = (profile.transport.get("tls_verify") or {}).get("mode") or "system"

    return {
        "schema": "test-plan/1",
        "mode": (mode.as_dict() if mode is not None else None),
        "destination": {
            "base_url": profile.base_url,
            "host": parsed.hostname,
            "port": port,
            "scheme": parsed.scheme,
            "path_prefix": parsed.path or "/",
            "transport": (profile.proxy if (via_proxy and profile.proxy)
                          else "direct (no proxy)"),
            "tls_verification": tls,
            "tls_warning": (
                "certificate validity will NOT be checked on this run"
                if tls == "insecure" else None),
            "client_certificate": (
                (profile.transport.get("client_cert") or {}).get("mode")
                or "none"),
        },
        "engagement": {
            "target_name": profile.name,
            "reference": (profile.data.get("identity") or {}).get(
                "engagement_ref", ""),
            "scope_policy": policy.spec.get("description", ""),
            "authorisations": [a.describe() for a in policy.authorisations],
            "denied_classes": sorted(policy.deny_classes),
            "mode_refusals": sorted(policy.hard_deny),
        },
        "identities": identities,
        "endpoints": endpoints,
        "requests": {
            "cases_built": len(list(cases)),
            "will_be_sent": len(permitted),
            "denied_by_scope_or_mode": len(denied),
            "data_changing": len(mutating),
            "by_payload_class": payload_classes,
        },
        "data_changing_operations": [
            {"case_id": c.id, "endpoint": c.endpoint, "method": c.method,
             "payload_class": getattr(c, "payload_class", ""),
             "description": c.description}
            for c in mutating
        ],
        "denials": denial_reasons,
        "limits": (limits.as_dict() if limits is not None else None),
        "limits_note": (limits.describe() if limits is not None else None),
        "nothing_sent_yet": True,
    }


def render(plan, max_mutating=20):
    """The plan as text, for a terminal or an approval e-mail."""
    out = []
    dest = plan["destination"]
    req = plan["requests"]

    out.append("TEST PLAN -- nothing has been sent")
    out.append("=" * 68)
    if plan.get("mode"):
        out.append("mode              %s -- %s"
                   % (plan["mode"]["mode"], plan["mode"]["summary"]))
    out.append("")
    out.append("DESTINATION")
    out.append("  target          %s (%s)" % (plan["engagement"]["target_name"],
                                              plan["engagement"]["reference"]
                                              or "no engagement reference"))
    out.append("  base url        %s" % dest["base_url"])
    out.append("  host:port       %s:%s" % (dest["host"], dest["port"]))
    out.append("  transport       %s" % dest["transport"])
    out.append("  tls             %s" % dest["tls_verification"])
    if dest.get("tls_warning"):
        out.append("                  ** %s **" % dest["tls_warning"])
    out.append("  client cert     %s" % dest["client_certificate"])

    out.append("")
    out.append("IDENTITIES (%d)" % len(plan["identities"]))
    for identity in plan["identities"]:
        out.append("  %-22s %s" % (identity["name"], identity["purpose"]))

    out.append("")
    out.append("ENDPOINTS")
    for endpoint in plan["endpoints"]:
        out.append("  %-22s %-28s %4d case(s), %d data-changing"
                   % (endpoint["id"], endpoint["path"],
                      endpoint["cases_to_send"],
                      endpoint["data_changing_cases"]))

    out.append("")
    out.append("REQUESTS")
    out.append("  built           %d" % req["cases_built"])
    out.append("  WILL BE SENT    %d" % req["will_be_sent"])
    out.append("  denied          %d (scope policy or engagement mode)"
               % req["denied_by_scope_or_mode"])
    out.append("  DATA-CHANGING   %d" % req["data_changing"])
    if req["by_payload_class"]:
        out.append("  payload classes %s"
                   % ", ".join("%s=%d" % kv for kv in
                               sorted(req["by_payload_class"].items())))

    if plan["data_changing_operations"]:
        out.append("")
        out.append("OPERATIONS THAT MAY CHANGE DATA")
        for row in plan["data_changing_operations"][:max_mutating]:
            out.append("  %-12s %-6s %-20s %s"
                       % (row["case_id"], row["method"], row["endpoint"],
                          row["description"][:44]))
        remaining = len(plan["data_changing_operations"]) - max_mutating
        if remaining > 0:
            out.append("  ... and %d more (see the written plan for the full "
                       "list)" % remaining)

    if plan["denials"]:
        out.append("")
        out.append("DENIED, AND WHY")
        for reason, count in sorted(plan["denials"].items(),
                                    key=lambda kv: -kv[1]):
            out.append("  %4d  %s" % (count, reason[:92]))

    if plan.get("limits_note"):
        out.append("")
        out.append("CEILINGS AND STOP CONDITIONS")
        out.append("  %s" % plan["limits_note"])

    auths = plan["engagement"]["authorisations"]
    out.append("")
    out.append("AUTHORISATIONS ON RECORD")
    if auths:
        for line in auths:
            out.append("  %s" % line)
    else:
        out.append("  none. Only classes the policy does not deny will run.")
    return "\n".join(out)
