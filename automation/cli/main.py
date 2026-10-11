"""apiscan -- command-line entry point.

Subcommands:

  init-engagement   scaffold an engagement workspace OUTSIDE the framework
  validate          validate a target profile and scope policy, send nothing
  preflight         readiness gate (add --offline to skip anything networked)
  generate          build a corpus and show what it would send, send nothing
  scan              execute a corpus and capture evidence
  reclassify        re-judge a completed run from stored responses, send nothing
  report            build the deliverable from a completed run
  capture           render PoC evidence from stored bytes
  snapshot          snapshot or roll back the framework

Two conventions hold throughout:

  * Anything that sends traffic requires an explicit target profile and obeys
    the engagement scope policy. ``generate`` and ``validate`` never send.
  * Engagement data is written only to paths the caller supplies, and the path
    guard refuses any path inside the framework tree.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from framework.core import auth as AUTH                       # noqa: E402
from framework.core import profile as PROFILE                 # noqa: E402
from framework.core.errors import FrameworkError              # noqa: E402
from framework.core.transport import Transport                # noqa: E402
from framework.corpus.case import Corpus                      # noqa: E402
from framework.corpus.generators import families as FAMILIES  # noqa: E402
from framework.corpus.generators import phases as PHASES      # noqa: E402
from framework.corpus.generators import retest as RETEST      # noqa: E402
from framework.evidence.store import EvidenceStore, find_latest_run  # noqa: E402
from framework.governance.scope import ScopePolicy            # noqa: E402


def _load_profile(args, strict_env=None):
    """Load the engagement profile.

    *strict_env* defaults to the ``--lax-env`` flag. A command that sends
    nothing may pass ``False``: re-judging stored bytes never authenticates to
    anything, so demanding live credentials to read a finished run is friction
    with no safety value -- and it bites hardest after an engagement, once the
    secrets have rightly been cleared from the environment.
    """
    if strict_env is None:
        strict_env = not getattr(args, "lax_env", False)
    return PROFILE.load(args.profile, strict_env=strict_env)


def _load_scope(args):
    if getattr(args, "scope", None):
        return ScopePolicy.load(args.scope)
    return ScopePolicy.default()


def _build_corpus(profile, auth_provider, args):
    cases = []
    if getattr(args, "baseline", True):
        cases += RETEST.baseline_cases(profile)
    fams = (args.families.split(",") if getattr(args, "families", None)
            else None)
    phase_ids = (args.phases.split(",") if getattr(args, "phases", None)
                 else None)
    if fams or not phase_ids:
        cases += FAMILIES.generate(profile, auth_provider=auth_provider,
                                   families=fams)
    if phase_ids or not fams:
        cases += PHASES.generate(profile, auth_provider,
                                 phase_ids=phase_ids,
                                 up_to=getattr(args, "up_to", None))
    corpus = Corpus(cases, "corpus")
    if getattr(args, "ids", None):
        corpus = Corpus(corpus.select(ids=args.ids.split(",")), "selected")
    if getattr(args, "endpoint", None):
        corpus = Corpus(corpus.select(endpoint=args.endpoint), "selected")
    return corpus


# -- commands ------------------------------------------------------------
def cmd_init_engagement(args):
    from framework.core.pathguard import ensure_engagement_dir
    root = ensure_engagement_dir(args.directory)
    for sub in ("evidence", "findings", "reports", "poc"):
        os.makedirs(os.path.join(root, sub), exist_ok=True)

    profile_src = os.path.join(ROOT, "configs", "examples",
                               "example-callback-api.json")
    profile_dst = os.path.join(root, "profile.json")
    if not os.path.exists(profile_dst):
        with open(profile_src) as fh:
            data = json.load(fh)
        data["identity"]["name"] = args.name or "engagement-target"
        data["identity"]["description"] = ("REPLACE THIS. Copied from the "
                                           "synthetic example profile.")
        data["identity"]["engagement_ref"] = args.reference or "REPLACE-ME"
        data["$comment"] = ("Engagement profile. Every value below is a "
                            "SYNTHETIC PLACEHOLDER copied from the example and "
                            "must be replaced. Credentials belong in .env as "
                            "${ENV:NAME} references, never inline.")
        with open(profile_dst, "w") as fh:
            json.dump(data, fh, indent=2)

    scope_dst = os.path.join(root, "scope-policy.json")
    if not os.path.exists(scope_dst):
        with open(scope_dst, "w") as fh:
            json.dump({
                "$comment": "Rules of engagement. Default-deny for anything "
                            "that changes state or generates volume. Add an "
                            "authorisation entry, naming who approved it and "
                            "against what reference, to permit a class.",
                "schema": "scope-policy/1",
                "description": "REPLACE: summarise the agreed rules of engagement",
                "deny_classes": ["state_mutating", "volumetric", "destructive",
                                 "infrastructure_pivot", "bulk_extraction"],
                "authorisations": [],
            }, fh, indent=2)

    env_dst = os.path.join(root, ".env")
    if not os.path.exists(env_dst):
        with open(env_dst, "w") as fh:
            fh.write("# Engagement credentials. NEVER commit this file.\n"
                     "# Referenced from profile.json as ${ENV:NAME}.\n"
                     "EXAMPLE_PRIMARY_ID=\n"
                     "EXAMPLE_PRIMARY_TOKEN=\n"
                     "EXAMPLE_WRONGROLE_ID=\n"
                     "EXAMPLE_WRONGROLE_TOKEN=\n"
                     "EXAMPLE_BADTOKEN_ID=\n"
                     "EXAMPLE_BADTOKEN_TOKEN=\n")
        os.chmod(env_dst, 0o600)

    gitignore = os.path.join(root, ".gitignore")
    if not os.path.exists(gitignore):
        with open(gitignore, "w") as fh:
            fh.write(".env\n*.p12\n*.key\n*.pem\n*.crt\nevidence/\nreports/\n"
                     "poc/\nfindings/\n")

    print("Engagement scaffolded at %s" % root)
    print()
    print("  profile.json       target description -- REPLACE the placeholders")
    print("  scope-policy.json  rules of engagement -- default-deny")
    print("  .env               credentials (mode 0600, gitignored)")
    print("  evidence/ findings/ reports/ poc/")
    print()
    print("This directory is OUTSIDE the framework. Client data stays here;")
    print("the framework stays reusable. Next:")
    print("  1. edit profile.json and scope-policy.json")
    print("  2. fill .env, then:  set -a; . %s/.env; set +a"
          % os.path.basename(root))
    print("  3. apiscan validate   --profile %s/profile.json"
          % os.path.basename(root))
    print("  4. apiscan preflight  --profile %s/profile.json"
          % os.path.basename(root))
    return 0


def cmd_validate(args):
    profile = _load_profile(args)
    print("profile OK: %s" % profile.name)
    print("  endpoints   : %s" % ", ".join(profile.endpoint_ids))
    print("  identities  : %s" % ", ".join(
        "%s(%s)" % (k, v.get("purpose")) for k, v in
        sorted(profile.identities.items())))
    print("  secrets     : %d reference(s) resolved from the environment"
          % len(profile.resolved_env))
    print("  envelope    : %s" % ("declared" if profile.envelope else "none"))
    policy = _load_scope(args)
    print("scope policy OK")
    print("  deny classes: %s" % ", ".join(sorted(policy.deny_classes)) or "-")
    print("  max risk    : %s" % (policy.max_risk or "unset"))
    print("  authorised  : %s" % (", ".join(
        a.describe() for a in policy.authorisations) or "none"))
    auth_provider = AUTH.from_profile(profile)
    corpus = _build_corpus(profile, auth_provider, args)
    permitted, skipped = policy.filter(list(corpus))
    print("corpus      : %d case(s); %d permitted, %d denied by scope"
          % (len(corpus), len(permitted), len(skipped)))
    print()
    print("Nothing was sent.")
    return 0


def cmd_preflight(args):
    from automation.preflight import checks as PF
    profile = _load_profile(args)
    ctx = {"profile": profile, "evidence_root": args.evidence,
           "offline": args.offline}
    if not args.offline:
        auth_provider = AUTH.from_profile(profile)
        ctx["transport"] = Transport(
            profile, auth_provider,
            body_dir=args.evidence or os.path.join(os.getcwd(), ".apiscan-tmp"),
            via_proxy=bool(profile.proxy))
    results, blocked = PF.run(ctx, stop_on_fail=not args.all,
                              quiet=args.json)
    if args.json:
        print(PF.to_json(results, ctx))
    else:
        print()
        print("summary: %s" % PF.summarise(results))
        print("READY" if not blocked else "NOT READY -- fix the blocker above")
    return 1 if blocked else 0


def cmd_generate(args):
    profile = _load_profile(args)
    auth_provider = AUTH.from_profile(profile)
    corpus = _build_corpus(profile, auth_provider, args)
    policy = _load_scope(args)
    via_proxy = bool(profile.proxy) and not getattr(args, "direct", False)
    permitted, skipped = policy.filter(list(corpus), via_proxy=via_proxy)

    if args.out:
        with open(args.out, "w") as fh:
            fh.write(corpus.to_json())
        print("corpus written to %s" % args.out)

    print("corpus: %d case(s)" % len(corpus))
    print("  by family  : %s" % corpus.counts("family"))
    print("  by phase   : %s" % corpus.counts("phase"))
    print("  by endpoint: %s" % corpus.counts("endpoint"))
    print("  mutating   : %d" % sum(1 for c in corpus if c.state_mutating))
    print("scope: %d permitted, %d denied" % (len(permitted), len(skipped)))
    for case, reason in skipped[:args.show_skipped]:
        print("  [deny] %-12s %s" % (case.id, reason))
    if len(skipped) > args.show_skipped:
        print("  ... and %d more" % (len(skipped) - args.show_skipped))
    if args.list:
        print()
        for case in corpus:
            print("  %-12s %-9s %-16s %-7s %-10s %s"
                  % (case.id, case.phase or case.family, case.endpoint,
                     case.method, case.expectation, case.description[:62]))
    print()
    print("Nothing was sent.")
    return 0


def cmd_scan(args):
    from framework import runner as RUN
    profile = _load_profile(args)
    auth_provider = AUTH.from_profile(profile)
    policy = _load_scope(args)
    corpus = _build_corpus(profile, auth_provider, args)

    store = EvidenceStore(args.evidence, metadata={
        "target": profile.name,
        "engagement": profile.data["identity"].get("engagement_ref", ""),
        "base_url": profile.base_url,
        "proxy": profile.proxy or "direct",
        "scope_policy": args.scope or "default (deny mutating/volumetric)",
        "verdict_policy": (profile.response_model.get("verdict_policy")
                           or "layered"),
        "operator_note": args.note or "",
    })
    runner = RUN.Runner(profile, auth_provider, store, scope_policy=policy,
                        via_proxy=bool(profile.proxy) and not args.direct)
    print("run %s -> %s" % (store.run_id, store.run_dir))
    print("target %s via %s | %d case(s)"
          % (profile.base_url,
             (profile.proxy if profile.proxy and not args.direct else "direct"),
             len(corpus)))
    print()
    records = runner.run(list(corpus),
                         progress=None if args.quiet else RUN.default_progress)
    manifest = store.finalise()

    summary = RUN.summarise(records)
    ok, baseline_summary = RETEST.assess_baseline(records)
    print()
    print("summary: %s" % json.dumps(summary["by_verdict"]))
    print("baseline: %s -- %s" % ("PASSED" if ok else "NOT PASSED",
                                  baseline_summary))
    if not ok:
        print()
        print("WARNING: negative results from this run are INCONCLUSIVE until")
        print("the baseline failure is explained.")
    print("evidence: %s (%d artifacts hashed)"
          % (store.run_dir, manifest["artifact_count"]))
    return 0


def cmd_reclassify(args):
    from framework import runner as RUN
    # Sends nothing: credential VALUES are irrelevant to re-judging stored
    # responses. The corpus is rebuilt for its case definitions only.
    profile = _load_profile(args, strict_env=False)
    auth_provider = AUTH.from_profile(profile)
    corpus = _build_corpus(profile, auth_provider, args)
    run_dir = args.run or find_latest_run(args.evidence)
    if not run_dir:
        print("no run found under %s" % args.evidence, file=sys.stderr)
        return 2
    records = RUN.reclassify(run_dir, list(corpus), profile,
                             verdict_policy=args.verdict_policy)
    out = os.path.join(run_dir, "results-reclassified.json")
    with open(out, "w") as fh:
        json.dump(records, fh, indent=2)
    # Register it, or the run fails its own integrity check from here on.
    from framework.evidence.store import EvidenceStore
    EvidenceStore.register_derived(run_dir, os.path.basename(out))
    print("re-judged %d stored response(s) from %s" % (len(records), run_dir))
    print("summary: %s" % json.dumps(RUN.summarise(records)["by_verdict"]))
    print("written: %s" % out)
    print()
    print("No request was sent.")
    return 0


def cmd_tls_posture(args):
    """Transport-layer posture, captured DIRECT and gated like any case.

    Runs outside the proxy by necessity: an intercepting proxy terminates TLS
    and presents its own configured client certificate, so a "no client
    certificate" probe sent through one silently acquires one and the finding
    stops reproducing. The capture method travels with the evidence so a
    report cannot claim otherwise.
    """
    from urllib.parse import urlparse
    from framework.evidence.provenance import CaptureMethod, provenance_line
    from framework.modules import tls_posture

    profile = _load_profile(args, strict_env=False)
    policy = _load_scope(args)
    endpoint = args.endpoint or profile.endpoint_ids[0]
    url = profile.url_for(endpoint)
    parsed = urlparse(profile.base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    store = EvidenceStore(args.evidence, metadata={
        "target": profile.name,
        "kind": "transport-posture",
        "capture_method": CaptureMethod.DIRECT,
        "endpoint": endpoint,
        "host": host, "port": port,
        "note": provenance_line(CaptureMethod.DIRECT, profile.name,
                                extra="proxy deliberately bypassed"),
    })

    sections = [
        ("client-cert-enforcement", lambda: tls_posture.client_cert_enforcement(
            url, cert_path=args.client_cert, key_path=args.client_key,
            untrusted_cert=args.untrusted_cert,
            untrusted_key=args.untrusted_key,
            scope_policy=policy, endpoint=endpoint)),
        ("negotiated", lambda: tls_posture.negotiated_parameters(
            host, port=port, scope_policy=policy, endpoint=endpoint)),
    ]
    if args.client_cert:
        sections.append(("revocation", lambda: tls_posture.certificate_revocation(
            args.client_cert)))
    if args.ciphers:
        sections.append(("ciphers", lambda: tls_posture.cipher_enumeration(
            host, port=port, scope_policy=policy, endpoint=endpoint)))

    findings = 0
    for name, run in sections:
        blob = run()
        path = os.path.join(store.run_dir, "tls-%s.json" % name)
        with open(path, "w") as fh:
            json.dump(blob, fh, indent=2, default=str)
        found = blob.get("findings") or ([blob["finding"]]
                                         if blob.get("finding") else [])
        findings += len(found)
        store.record({"case_id": "tls-%s" % name, "executed": True,
                      "verdict": "OBSERVED", "section": name,
                      "status": blob.get("status"),
                      "capture_method": CaptureMethod.DIRECT,
                      "findings": len(found)})
        if not args.quiet:
            print("  %-26s %s" % (name, blob.get("status", "?")))
            for f in found:
                print("      - [%s] %s" % (f.get("severity", "?"),
                                           f.get("title", "")))

    store.finalise()
    if not args.quiet:
        print()
        print("%d transport observation(s), %d finding(s)"
              % (len(sections), findings))
        print("captured DIRECT (not via proxy); evidence -> %s"
              % store.run_dir)
    return 0


def cmd_report(args):
    from framework.findings.coverage import Coverage
    from framework.findings.register import Register
    from framework.reporting.model import ReportModel
    from framework.reporting.renderers import csvout, markdown, xlsx

    run_dir = args.run or find_latest_run(args.evidence)
    if not run_dir:
        print("no run found under %s" % args.evidence, file=sys.stderr)
        return 2
    with open(os.path.join(run_dir, "results.json")) as fh:
        records = json.load(fh)
    meta = {}
    meta_path = os.path.join(run_dir, "run.json")
    if os.path.exists(meta_path):
        with open(meta_path) as fh:
            meta = json.load(fh)

    entries = []
    if args.register and os.path.exists(args.register):
        from framework.findings.register import Entry
        with open(args.register) as fh:
            for spec in json.load(fh):
                entries.append(Entry(**spec))

    register = Register(entries=entries, records=records,
                        strict=not args.lax_register)
    if args.promote:
        register.promote_machine_findings()
    register.build()

    ok, baseline_summary = RETEST.assess_baseline(records)
    not_established = []
    if args.not_established and os.path.exists(args.not_established):
        with open(args.not_established) as fh:
            not_established = [ln.strip() for ln in fh if ln.strip()]
    coverage = Coverage(records, baseline_ok=ok,
                        baseline_summary=baseline_summary,
                        not_established=not_established)

    model = ReportModel(
        args.engagement or meta.get("engagement") or "unnamed engagement",
        meta.get("target", "unnamed target"), register, coverage,
        records=records, run_metadata=meta, scope_note=args.scope_note or "")

    os.makedirs(args.out, exist_ok=True)
    written = [markdown.write(model, os.path.join(args.out, "report.md"))]
    written += csvout.write(model, args.out)
    if xlsx.available() and not args.no_xlsx:
        result = xlsx.write(model, os.path.join(args.out, "report.xlsx"))
        written.append(result.path)
        for note in result.notes:
            print("NOTE: %s" % note)
    elif not args.no_xlsx:
        print("NOTE: openpyxl is not installed, so no workbook was produced. "
              "Markdown and CSV were written instead.")

    problems = model.validate()
    print()
    for path in written:
        print("  wrote %s" % path)
    print()
    if problems:
        print("THIS REPORT IS NOT ISSUABLE AS IT STANDS:")
        for p in problems:
            print("  - %s" % p)
        return 1
    print("Report is issuable.")
    return 0


def cmd_capture(args):
    from framework.evidence.provenance import CaptureMethod, provenance_line
    from tools.capture import render
    run_dir = args.run or find_latest_run(args.evidence)
    if not run_dir:
        print("no run found under %s" % args.evidence, file=sys.stderr)
        return 2
    with open(os.path.join(run_dir, "results.json")) as fh:
        records = {r["case_id"]: r for r in json.load(fh)}
    meta_path = os.path.join(run_dir, "run.json")
    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path) as fh:
            meta = json.load(fh)

    wanted = args.ids.split(",") if args.ids else [
        cid for cid, r in records.items()
        if r.get("verdict") == "CONTROL-ABSENT" or r.get("detector_hits")]
    os.makedirs(args.out, exist_ok=True)
    made = 0
    for case_id in wanted:
        rec = records.get(case_id)
        if not rec:
            print("  %-12s not in this run" % case_id)
            continue
        files = [os.path.join(os.path.dirname(run_dir), p)
                 for p in (rec.get("request_file"), rec.get("response_file"))
                 if p]
        files = [f for f in files if os.path.exists(f)]
        if not files:
            print("  %-12s no stored bytes" % case_id)
            continue
        method = CaptureMethod.DERIVED
        prov = provenance_line(method, meta.get("target", "unspecified"),
                               extra="run %s" % meta.get("run_id", ""))
        title = render.headline_title(case_id, rec.get("description", ""))
        subtitle = ("layer %s | verdict %s | original capture: %s"
                    % (rec.get("layer"), rec.get("verdict"),
                       rec.get("capture_method")))
        highlight = [h["excerpt"] for h in (rec.get("detector_hits") or [])]
        base = os.path.join(args.out, "%s-rendered" % case_id)
        render.write_html(base + ".html", title, files, prov, subtitle,
                          highlight)
        ok, detail = render.render_png(base + ".png", title, files, prov,
                                       subtitle, highlight)
        made += 1
        print("  %-12s html%s" % (case_id, "  png" if ok else
                                  "  (png NOT produced: %s)" % detail[:60]))
    print()
    print("%d artifact set(s) in %s" % (made, args.out))
    print("All artifacts are DERIVED from stored bytes; no traffic was sent.")
    return 0


def cmd_snapshot(args):
    from automation.maintenance import snapshot
    if args.action == "create":
        path = snapshot.create(args.label or "manual", args.store)
        print("snapshot created: %s" % path)
    elif args.action == "list":
        for snap in snapshot.listing(args.store):
            print("  %-26s %s  %d files" % (snap["id"], snap["created"],
                                            snap["file_count"]))
    elif args.action == "rollback":
        if not args.id:
            print("--id is required for rollback", file=sys.stderr)
            return 2
        restored = snapshot.rollback(args.id, args.store)
        print("rolled back to %s (%d files restored)" % (args.id, restored))
    return 0


# -- parser --------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="apiscan",
        description="Reusable API security assessment framework.")
    sub = p.add_subparsers(dest="command", required=True)

    def add_profile(sp, required=True):
        sp.add_argument("--profile", required=required,
                        help="path to the engagement target profile")
        sp.add_argument("--scope", help="path to the engagement scope policy")
        sp.add_argument("--lax-env", action="store_true",
                        help="do not fail on unresolved ${ENV:...} references")

    def add_corpus(sp):
        sp.add_argument("--families", help="comma-separated family letters A-J")
        sp.add_argument("--phases", help="comma-separated phase ids P1-P7")
        sp.add_argument("--up-to", help="run phases up to and including this one")
        sp.add_argument("--ids", help="comma-separated case ids")
        sp.add_argument("--endpoint", help="restrict to one endpoint id")
        sp.add_argument("--no-baseline", dest="baseline", action="store_false",
                        help="omit baseline calibration cases (not advised: "
                             "without them a negative result cannot be "
                             "distinguished from a broken harness)")

    sp = sub.add_parser("init-engagement",
                        help="scaffold an engagement workspace")
    sp.add_argument("directory")
    sp.add_argument("--name", help="target name")
    sp.add_argument("--reference", help="engagement reference")
    sp.set_defaults(func=cmd_init_engagement)

    sp = sub.add_parser("validate", help="validate configuration; sends nothing")
    add_profile(sp)
    add_corpus(sp)
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("preflight", help="readiness gate")
    add_profile(sp)
    sp.add_argument("--evidence", help="engagement evidence directory")
    sp.add_argument("--offline", action="store_true",
                    help="skip every networked check")
    sp.add_argument("--all", action="store_true",
                    help="run every check instead of stopping at the first "
                         "blocker")
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.set_defaults(func=cmd_preflight)

    sp = sub.add_parser("generate", help="build a corpus; sends nothing")
    add_profile(sp)
    add_corpus(sp)
    sp.add_argument("--out", help="write the corpus as JSON")
    sp.add_argument("--list", action="store_true", help="list every case")
    sp.add_argument("--show-skipped", type=int, default=10)
    sp.set_defaults(func=cmd_generate)

    sp = sub.add_parser("scan", help="execute a corpus and capture evidence")
    add_profile(sp)
    add_corpus(sp)
    sp.add_argument("--evidence", required=True,
                    help="engagement evidence directory (outside the framework)")
    sp.add_argument("--direct", action="store_true",
                    help="bypass the proxy for this run")
    sp.add_argument("--note", help="operator note recorded in run metadata")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("reclassify",
                        help="re-judge a stored run; sends nothing")
    add_profile(sp)
    add_corpus(sp)
    sp.add_argument("--evidence", required=True)
    sp.add_argument("--run", help="run directory (default: latest)")
    sp.add_argument("--verdict-policy", choices=["layered", "validation_strict"])
    sp.set_defaults(func=cmd_reclassify)

    sp = sub.add_parser("report", help="build the deliverable")
    sp.add_argument("--evidence", required=True)
    sp.add_argument("--run", help="run directory (default: latest)")
    sp.add_argument("--out", required=True, help="output directory")
    sp.add_argument("--register", help="authored findings register JSON")
    sp.add_argument("--not-established",
                    help="text file, one limitation per line (REQUIRED for an "
                         "issuable report)")
    sp.add_argument("--scope-note", help="rules of engagement summary")
    sp.add_argument("--engagement", help="engagement name")
    sp.add_argument("--promote", action="store_true",
                    help="promote machine findings into the register")
    sp.add_argument("--lax-register", action="store_true",
                    help="warn instead of failing when a register entry cites "
                         "an unknown case id")
    sp.add_argument("--no-xlsx", action="store_true")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("capture", help="render PoC evidence from stored bytes")
    sp.add_argument("--evidence", required=True)
    sp.add_argument("--run", help="run directory (default: latest)")
    sp.add_argument("--out", required=True)
    sp.add_argument("--ids", help="comma-separated case ids (default: every "
                                  "case with a finding or detector hit)")
    sp.set_defaults(func=cmd_capture)

    sp = sub.add_parser("tls-posture",
                        help="transport-layer posture; always DIRECT")
    sp.add_argument("--profile", required=True)
    sp.add_argument("--scope", help="path to the engagement scope policy")
    sp.add_argument("--lax-env", action="store_true")
    sp.add_argument("--evidence", required=True,
                    help="engagement evidence directory (outside the framework)")
    sp.add_argument("--endpoint", help="endpoint id to probe (default: first)")
    sp.add_argument("--client-cert", help="issued client certificate (PEM)")
    sp.add_argument("--client-key", help="issued client key (PEM)")
    sp.add_argument("--untrusted-cert",
                    help="self-signed certificate, to test chain validation")
    sp.add_argument("--untrusted-key")
    sp.add_argument("--ciphers", action="store_true",
                    help="enumerate ciphers (needs nmap or testssl.sh)")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_tls_posture)

    sp = sub.add_parser("snapshot", help="snapshot or roll back the framework")
    sp.add_argument("action", choices=["create", "list", "rollback"])
    sp.add_argument("--id", help="snapshot id to roll back to")
    sp.add_argument("--label", help="label for a new snapshot")
    sp.add_argument("--store", help="snapshot store directory")
    sp.set_defaults(func=cmd_snapshot)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FrameworkError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
