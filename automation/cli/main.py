"""apiscan -- command-line entry point.

Subcommands and what each one actually does are declared ONCE, in
``COMMANDS`` below, and every other statement of that -- ``apiscan commands``,
the tables in CLAUDE.md, README.md and the skill -- is checked against it by
``tests/regression/test_documentation_matches_code.py``. The previous
arrangement had the same table written out in four prose files, and they had
already drifted: CLAUDE.md said two commands send traffic while the skill
correctly noted that preflight sends as well. A reader following the wrong one
believed a readiness check was free.

Three conventions hold throughout:

  * Anything that sends traffic requires an explicit target profile, an
    engagement scope policy, and an engagement MODE. The mode defaults to the
    cautious one, so an omitted flag narrows the run rather than widening it.
  * Every request passes the scope gate inside the transport, so no command
    can reach the network around it -- including preflight.
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
from framework.evidence.store import EvidenceStore              # noqa: E402
from framework.governance.scope import (DEFAULT_DENY,          # noqa: E402
                                        ScopePolicy)


#: The single authoritative statement of what each subcommand does.
#:
#: ``sends_traffic``  does invoking this command open a socket to the target?
#: ``writes_files``   does it create or modify files on disk?
#: ``needs_scope``    is an engagement scope policy required (not optional)?
#:
#: ENGINEERING IMPROVEMENT (review finding: "clearly identify every command
#: that sends traffic or changes files" and "keep one authoritative workflow
#: and derive the other guides from it").
COMMANDS = {
    "init-engagement": {
        "sends_traffic": False, "writes_files": True, "needs_scope": False,
        "summary": "scaffold an engagement workspace outside the framework"},
    "validate": {
        "sends_traffic": False, "writes_files": False, "needs_scope": False,
        "summary": "validate the profile and scope policy; send nothing"},
    "plan": {
        "sends_traffic": False, "writes_files": True, "needs_scope": True,
        "summary": "write the reviewable test plan a live run would execute"},
    "generate": {
        "sends_traffic": False, "writes_files": True, "needs_scope": False,
        "summary": "build the corpus and show what it would send; send "
                   "nothing (writes files only with --out)"},
    "preflight": {
        "sends_traffic": True, "writes_files": True, "needs_scope": True,
        "summary": "readiness gate; sends a small number of gated probes "
                   "unless --offline"},
    "scan": {
        "sends_traffic": True, "writes_files": True, "needs_scope": True,
        "summary": "execute the corpus and capture evidence"},
    "tls-posture": {
        "sends_traffic": True, "writes_files": True, "needs_scope": True,
        "summary": "transport-layer posture; always captured DIRECT"},
    "reclassify": {
        "sends_traffic": False, "writes_files": True, "needs_scope": False,
        "summary": "re-judge a stored run from captured bytes; send nothing"},
    "report": {
        "sends_traffic": False, "writes_files": True, "needs_scope": False,
        "summary": "build the deliverable from one named run"},
    "capture": {
        "sends_traffic": False, "writes_files": True, "needs_scope": False,
        "summary": "render PoC evidence from stored bytes"},
    "redact": {
        "sends_traffic": False, "writes_files": True, "needs_scope": False,
        "summary": "write a redacted copy of a run for distribution; the raw "
                   "originals are left unmodified"},
    "purge": {
        "sends_traffic": False, "writes_files": True, "needs_scope": False,
        "summary": "delete evidence past its retention date (dry run unless "
                   "--force)"},
    "verify": {
        "sends_traffic": False, "writes_files": False, "needs_scope": False,
        "summary": "re-hash a run against its evidence manifest"},
    "snapshot": {
        "sends_traffic": False, "writes_files": True, "needs_scope": False,
        "summary": "snapshot or roll back the framework source"},
    "commands": {
        "sends_traffic": False, "writes_files": False, "needs_scope": False,
        "summary": "print this table, which is the authoritative one"},
    "version": {
        "sends_traffic": False, "writes_files": False, "needs_scope": False,
        "summary": "version, commit, environment and optional-dependency "
                   "status"},
}

TRAFFIC_COMMANDS = sorted(k for k, v in COMMANDS.items() if v["sends_traffic"])


GENERATED_TABLE_BEGIN = "<!-- BEGIN GENERATED COMMAND TABLE -->"
GENERATED_TABLE_END = "<!-- END GENERATED COMMAND TABLE -->"


def command_table_markdown():
    """The command table as Markdown, for embedding in the prose docs.

    Every document that states which commands send traffic embeds the output
    of this function between the BEGIN/END markers, and
    ``tests/regression/test_documentation_matches_code.py`` regenerates it and
    compares. That is the mechanism that stops the drift the review found:
    CLAUDE.md claimed two commands send traffic while the skill correctly
    listed three, and nothing could tell which was right.
    """
    lines = [GENERATED_TABLE_BEGIN,
             "",
             "| Command | Sends traffic | Writes files | Scope policy | What it does |",
             "|---|---|---|---|---|"]
    for name in sorted(COMMANDS):
        spec = COMMANDS[name]
        lines.append("| `%s` | %s | %s | %s | %s |"
                     % (name,
                        "**YES**" if spec["sends_traffic"] else "no",
                        "yes" if spec["writes_files"] else "no",
                        "**required**" if spec["needs_scope"] else "optional",
                        spec["summary"]))
    lines += ["",
              "Generated from `automation/cli/main.py:COMMANDS` by "
              "`apiscan commands --markdown`. Do not edit by hand; the test "
              "suite regenerates and compares it.",
              GENERATED_TABLE_END]
    return "\n".join(lines)


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


def _load_scope(args, require=False):
    """Load the engagement scope policy.

    *require* is set by the commands that send traffic. They used to fall back
    to the default-deny policy, which is safe but misleading: a run that
    silently used a default policy produced an evidence record citing
    "default (deny mutating/volumetric)" as its rules of engagement, and no
    reviewer could tell whether the client's actual policy had been consulted
    or forgotten. Naming the file is cheap and it is the audit record.
    """
    if getattr(args, "scope", None):
        return ScopePolicy.load(args.scope)
    if require:
        raise FrameworkError(
            "--scope is required by this command. Point it at the "
            "engagement's scope-policy.json: it is the record of what the "
            "client authorised, and it is what every request is checked "
            "against. `apiscan init-engagement` writes a default-deny policy "
            "to start from.")
    return ScopePolicy.default()


def _load_mode(args):
    from framework.governance import modes as MODES
    return MODES.get(getattr(args, "mode", None))


def _selectors(args):
    return {k: getattr(args, k, None)
            for k in ("ids", "families", "phases", "endpoint")}


def _effective_limits(mode, args):
    """The mode's ceilings, tightened by any the operator asked for."""
    return mode.limits.replace(
        max_cases=getattr(args, "max_cases", None),
        max_duration_s=getattr(args, "max_duration_s", None),
        max_response_bytes=getattr(args, "max_response_bytes", None),
        min_delay_s=getattr(args, "delay_s", None),
        max_consecutive_server_errors=getattr(
            args, "stop_after_server_errors", None))


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


def _resolve_run(args, kind="corpus"):
    """The run this command will act on, named explicitly or chosen aloud.

    ENGINEERING IMPROVEMENT (review finding: "use explicit run IDs for reports
    so a later TLS check cannot accidentally replace the intended scan
    results").

    ``report`` and ``capture`` used to default to whatever ran last. A
    ``tls-posture`` run is two transport observations and is very often the
    last thing an assessor does before writing up, so the deliverable was
    quietly built from it: an issuable-looking report whose tally described
    nothing. Now the run is either named with --run, or chosen with --latest,
    which restricts itself to runs of the right KIND and prints which one it
    picked.
    """
    from framework.evidence.store import list_runs, run_kind
    if getattr(args, "run", None):
        run_dir = args.run
        if not os.path.isdir(run_dir):
            candidate = os.path.join(args.evidence, str(args.run))
            if os.path.isdir(candidate):
                run_dir = candidate
            else:
                raise FrameworkError(
                    "no such run: %r (looked for it as a path and under %s)"
                    % (args.run, args.evidence))
        found = run_kind(run_dir)
        if kind and found and found != kind:
            print("NOTE: run %s records kind %r, not %r. Proceeding because "
                  "you named it explicitly."
                  % (os.path.basename(run_dir), found, kind), file=sys.stderr)
        return run_dir

    if not getattr(args, "latest", False):
        available = list_runs(args.evidence, kind=kind)
        hint = ""
        if available:
            hint = ("\nRuns of kind %r under that directory, oldest first:\n  %s"
                    % (kind, "\n  ".join(os.path.basename(r)
                                          for r in available[-8:])))
        raise FrameworkError(
            "name the run with --run <run-id>, or pass --latest to use the "
            "most recent run of kind %r. Defaulting to 'whatever ran last' is "
            "how a transport-posture run ends up being reported as the "
            "assessment.%s" % (kind, hint))

    runs = list_runs(args.evidence, kind=kind)
    if not runs:
        others = list_runs(args.evidence)
        extra = ""
        if others:
            extra = (" There are %d run(s) there, but none records kind %r; "
                     "name one with --run if that is what you want."
                     % (len(others), kind))
        raise FrameworkError("no run of kind %r found under %s.%s"
                             % (kind, args.evidence, extra))
    chosen = runs[-1]
    print("using run %s (latest of kind %r, of %d)"
          % (os.path.basename(chosen), kind, len(runs)))
    return chosen


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
                # Derived, never hand-typed: a scaffold that denied less
                # than the framework's own default would hand every new
                # engagement a quietly weaker starting policy.
                "deny_classes": list(DEFAULT_DENY),
                "retention_days": 90,
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
    """Readiness gate. SENDS TRAFFIC unless --offline.

    The scope policy is required when this command may send, because it does
    send: a POST to the first endpoint, a well-formed baseline body, and -- if
    fidelity probing is enabled in the profile -- a 200 KB body, a NUL byte
    and a truncated document. Each of those is now a declared probe judged by
    the policy before it leaves.
    """
    from automation.preflight import checks as PF
    profile = _load_profile(args)
    policy = _load_scope(args, require=not args.offline)
    mode = _load_mode(args)
    if not args.offline:
        policy = policy.with_mode(mode)
    via_proxy = bool(profile.proxy)
    ctx = {"profile": profile, "evidence_root": args.evidence,
           "offline": args.offline, "scope_policy": policy,
           "via_proxy": via_proxy, "mode": mode}
    if not args.offline:
        mode.assert_may_send()
        auth_provider = AUTH.from_profile(profile)
        ctx["transport"] = Transport(
            profile, auth_provider,
            body_dir=args.evidence or os.path.join(os.getcwd(), ".apiscan-tmp"),
            scope_policy=policy, via_proxy=via_proxy,
            limits=_effective_limits(mode, args))
    results, blocked = PF.run(ctx, stop_on_fail=not args.all,
                              quiet=args.json)
    if args.json:
        print(PF.to_json(results, ctx))
    else:
        print()
        print("summary: %s" % PF.summarise(results))
        unverified = [r for r in results if r.status == PF.NOT_VERIFIED]
        if unverified:
            print("%d check(s) were NOT VERIFIED -- not the same as passing:"
                  % len(unverified))
            for result in unverified:
                print("  ---- %s: %s" % (result.name, result.detail[:88]))
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
    """Execute the corpus. SENDS TRAFFIC.

    The order here is deliberate: build everything, show the operator exactly
    what would go out, get a decision, and only then open a socket. Every step
    before the confirmation is offline.
    """
    from framework import runner as RUN
    from framework.governance import plan as PLAN

    profile = _load_profile(args)
    auth_provider = AUTH.from_profile(profile)
    policy = _load_scope(args, require=True)
    mode = _load_mode(args)
    mode.assert_may_send()
    mode.assert_selection(_selectors(args))
    effective = policy.with_mode(mode)
    limits = _effective_limits(mode, args)
    corpus = _build_corpus(profile, auth_provider, args)
    via_proxy = bool(profile.proxy) and not args.direct

    the_plan = PLAN.build(profile, list(corpus), effective, mode=mode,
                          limits=limits, via_proxy=via_proxy)

    # Limits that are knowable BEFORE the run are recorded with it, so the
    # report states them without depending on the operator remembering. The
    # two that matter: data-changing cases whose resulting state cannot be
    # read back, and object-level authorisation with no controlled resource
    # to test it against.
    from framework.corpus.generators import verification as VERIFY
    verify_plan = VERIFY.plan_for(profile, list(corpus))
    _, ownership_note = VERIFY.ownership_cases(profile)
    auto_limits = list(verify_plan["not_established"])
    if ownership_note.startswith("object-level authorisation was NOT TESTED"):
        auto_limits.append(ownership_note)
    if not args.quiet and auto_limits:
        print("LIMITS OF THIS RUN, recorded with the evidence:")
        for line in auto_limits:
            print("  - %s" % line)
        print()
    if not args.quiet:
        print(PLAN.render(the_plan))
        print()
    if the_plan["requests"]["will_be_sent"] == 0:
        print("Nothing is permitted to be sent. Nothing was sent.")
        print("Every case was denied by the scope policy or the engagement "
              "mode; the reasons are listed above. Widening a scope policy to "
              "make a run proceed is not the fix -- ask the operator.")
        return 1

    if not _confirm(args, the_plan):
        print("Aborted. Nothing was sent.")
        return 1

    store = EvidenceStore(args.evidence, retention_days=args.retention_days,
                          metadata={
        "kind": "corpus",
        "target": profile.name,
        "engagement": profile.data["identity"].get("engagement_ref", ""),
        "base_url": profile.base_url,
        "proxy": profile.proxy or "direct",
        "scope_policy": args.scope,
        "engagement_mode": mode.name,
        "mode_refusals": sorted(effective.hard_deny),
        "limits": limits.as_dict(),
        "tls_verification": (profile.transport.get("tls_verify") or {}).get(
            "mode") or "system",
        "verdict_policy": (profile.response_model.get("verdict_policy")
                           or "layered"),
        "operator_note": args.note or "",
        "build": __import__("framework.environment", fromlist=["x"])
            .evidence_stamp(),
        "plan": the_plan,
        "state_verification": verify_plan,
        "ownership_note": ownership_note,
        "auto_not_established": auto_limits,
    })
    runner = RUN.Runner(profile, auth_provider, store, scope_policy=policy,
                        via_proxy=via_proxy, mode=mode, limits=limits)
    print("run %s -> %s" % (store.run_id, store.run_dir))
    print("target %s via %s | %d case(s) | mode %s"
          % (profile.base_url,
             (profile.proxy if profile.proxy and not args.direct else "direct"),
             len(corpus), mode.name))
    print()
    records = runner.run(list(corpus),
                         progress=None if args.quiet else RUN.default_progress)
    store.metadata["budget"] = runner.stop_report()
    manifest = store.finalise()
    from framework.core.transport import cleanup_scratch
    cleanup_scratch(store.run_dir)

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
    stopped = runner.budget.stopped_reason
    if stopped:
        print()
        print("RUN STOPPED EARLY: %s" % stopped)
        print("%d case(s) were never sent and are recorded NOT-REACHED. The "
              "assessment is INCOMPLETE; list the untested cases in the "
              "report's 'not established' section."
              % summary.get("not_reached", 0))
    print("evidence: %s (%d artifacts hashed, mode 0600, retain until %s)"
          % (store.run_dir, manifest["artifact_count"],
             store.metadata.get("retain_until") or "unset"))
    print("to share any of this, run `apiscan redact` first -- raw evidence "
          "contains credentials in the trace files.")
    return 0


def _confirm(args, the_plan):
    """Require a human decision before the first request leaves.

    ENGINEERING IMPROVEMENT (review finding: "before execution, show the
    actual destination, endpoints, identities, request count, and potentially
    data-changing operations").

    Skipped by --yes, which is what a pipeline uses, and skipped when stdin is
    not a terminal -- a prompt nobody can answer would otherwise hang a CI job
    forever. In both of those cases the plan has still been printed, so the
    record of what was about to be sent exists either way.
    """
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        print("stdin is not a terminal, so the plan above was not confirmed "
              "interactively. Proceeding because a non-interactive caller "
              "cannot answer; pass --yes to make that explicit.")
        return True
    dest = the_plan["destination"]
    prompt = ("Send %d request(s) to %s:%s, of which %d may change data? "
              "[y/N] " % (the_plan["requests"]["will_be_sent"], dest["host"],
                          dest["port"], the_plan["requests"]["data_changing"]))
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def cmd_plan(args):
    """Write the reviewable test plan. Sends nothing."""
    from framework.governance import plan as PLAN
    profile = _load_profile(args, strict_env=False)
    auth_provider = AUTH.from_profile(profile)
    policy = _load_scope(args, require=True)
    mode = _load_mode(args)
    corpus = _build_corpus(profile, auth_provider, args)
    via_proxy = bool(profile.proxy) and not getattr(args, "direct", False)
    the_plan = PLAN.build(profile, list(corpus), policy.with_mode(mode),
                          mode=mode, limits=_effective_limits(mode, args),
                          via_proxy=via_proxy)
    print(PLAN.render(the_plan))
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(the_plan, fh, indent=2, default=str)
        print()
        print("plan written to %s" % args.out)
    print()
    print("Nothing was sent.")
    return 0


def cmd_reclassify(args):
    from framework import runner as RUN
    # Sends nothing: credential VALUES are irrelevant to re-judging stored
    # responses. The corpus is rebuilt for its case definitions only.
    profile = _load_profile(args, strict_env=False)
    auth_provider = AUTH.from_profile(profile)
    corpus = _build_corpus(profile, auth_provider, args)
    run_dir = _resolve_run(args, kind="corpus")
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
    policy = _load_scope(args, require=True)
    mode = _load_mode(args)
    mode.assert_may_send()
    policy = policy.with_mode(mode)
    endpoint = args.endpoint or profile.endpoint_ids[0]
    url = profile.url_for(endpoint)
    parsed = urlparse(profile.base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    store = EvidenceStore(args.evidence,
                          retention_days=args.retention_days, metadata={
        "target": profile.name,
        "kind": "transport-posture",
        "engagement_mode": mode.name,
        "build": __import__("framework.environment", fromlist=["x"])
            .evidence_stamp(),
        "report_warning": (
            "This run records TRANSPORT observations, not an assessment of "
            "the application. `apiscan report` will not build a deliverable "
            "from it unless it is named explicitly with --run."),
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
        print("run id %s, kind 'transport-posture'. `apiscan report "
              "--latest` will NOT pick this up: it looks for a corpus run."
              % store.run_id)
    return 0


def cmd_report(args):
    from framework.findings.coverage import Coverage
    from framework.findings.register import Register
    from framework.reporting.model import ReportModel
    from framework.reporting.renderers import csvout, markdown, xlsx

    run_dir = _resolve_run(args, kind="corpus")
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
    # Limits the RUN recorded about itself are merged in automatically. They
    # are the ones most easily forgotten when the report is written days
    # later, and they are the ones a reader most needs.
    for line in (meta.get("auto_not_established") or []):
        if line not in not_established:
            not_established.append(line)
    budget = meta.get("budget") or {}
    if budget.get("stopped_reason"):
        line = ("the run stopped before completing: %s"
                % budget["stopped_reason"])
        if line not in not_established:
            not_established.append(line)
    if (meta.get("tls_verification") or "") == "insecure":
        line = ("certificate validity was not checked during this run "
                "(transport.tls_verify.mode was 'insecure'), so nothing here "
                "establishes the identity of the host that answered")
        if line not in not_established:
            not_established.append(line)
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
    run_dir = _resolve_run(args, kind="corpus")
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
        # The paths come out of results.json, which is a FILE -- data, not
        # a trusted constant. Resolve each one under the evidence root and
        # refuse anything that climbs out of it.
        from framework.core.errors import PathGuardError
        from framework.core.pathguard import safe_relative_join
        evidence_root = os.path.dirname(run_dir)
        files = []
        for rel in (rec.get("request_file"), rec.get("response_file")):
            if not rel:
                continue
            try:
                resolved = safe_relative_join(evidence_root, rel,
                                              what="stored evidence path")
            except PathGuardError as exc:
                print("  %-12s refusing a stored path that escapes the "
                      "evidence root: %s" % (case_id, exc))
                continue
            if os.path.exists(resolved):
                files.append(resolved)
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


def cmd_redact(args):
    """Write a redacted copy of a run for distribution. Sends nothing.

    The raw run is never touched: its evidence manifest must keep verifying,
    and redacting the only original would destroy the thing a third party
    would later check a finding against.
    """
    from framework.evidence import redact as RD
    run_dir = _resolve_run(args, kind=args.kind)
    profile = None
    provenance = {"source_kind": args.kind}
    if args.profile:
        profile = _load_profile(args, strict_env=False)
    if profile is not None:
        redactor, note = RD.from_profile(profile, include_pii=args.pii)
        provenance.update(note)
        if note["env_values_available"] < len(
                note["env_references_in_profile"]):
            print("NOTE: %d of %d credential value(s) referenced by the "
                  "profile are not in the environment, so they cannot be "
                  "matched as literals. Shape- and header-based redaction "
                  "still applies. Re-run with the engagement .env loaded for "
                  "the strongest result."
                  % (len(note["env_references_in_profile"])
                     - note["env_values_available"],
                     len(note["env_references_in_profile"])))
    else:
        redactor = RD.Redactor(include_pii=args.pii)
        print("NOTE: no --profile given, so this engagement's specific "
              "credential VALUES are not known to the redactor. Credential "
              "headers and credential shapes are still removed. Pass "
              "--profile for the strongest result.")

    manifest = RD.redact_run(run_dir, args.out, redactor,
                             provenance=provenance)
    print()
    print("redacted copy of %s -> %s"
          % (os.path.basename(run_dir), args.out))
    print("  %d artifact(s); replacements: %s"
          % (manifest["artifact_count"],
             json.dumps(manifest["redaction_totals"]) or "none"))
    for problem in manifest["problems"]:
        print("  PROBLEM: %s" % problem)
    print("  the raw run is unmodified and still verifies")
    if not manifest["redaction_totals"]:
        print()
        print("Nothing matched. That is worth a second look: trace files "
              "normally contain the Authorization header of every request. "
              "Confirm this run captured traces before treating the copy as "
              "safe to share.")
    print()
    print("No request was sent.")
    return 0


def cmd_purge(args):
    """Delete evidence past its retention date. Dry run unless --force.

    ENGINEERING IMPROVEMENT (review finding: "raw evidence has restricted
    access and a defined retention period"). A retention period nothing
    enforces is a sentence in a policy document. This is the enforcement, and
    it is deliberately awkward: it reports by default and deletes only when
    told to, because the thing it deletes is the evidence behind a finding.
    """
    import datetime
    import shutil

    from framework.core.pathguard import ensure_engagement_dir
    from framework.evidence.store import list_runs, restrict

    root = ensure_engagement_dir(args.evidence, create=False)
    today = (datetime.date.fromisoformat(args.as_of) if args.as_of
             else datetime.date.today())
    expired, kept, unknown = [], [], []
    for run_dir in list_runs(root):
        meta_path = os.path.join(run_dir, "run.json")
        retain_until = None
        if os.path.isfile(meta_path):
            try:
                with open(meta_path) as fh:
                    retain_until = json.load(fh).get("retain_until")
            except (ValueError, OSError):
                retain_until = None
        if not retain_until:
            unknown.append(run_dir)
            continue
        try:
            until = datetime.date.fromisoformat(retain_until)
        except ValueError:
            unknown.append(run_dir)
            continue
        (expired if today > until else kept).append((run_dir, retain_until))

    print("evidence root %s, as of %s" % (root, today.isoformat()))
    print("  %d run(s) within retention" % len(kept))
    for run_dir, until in kept:
        print("      keep   %-24s until %s" % (os.path.basename(run_dir),
                                               until))
    if unknown:
        print("  %d run(s) with NO recorded retention date -- these are never "
              "deleted automatically:" % len(unknown))
        for run_dir in unknown:
            print("      ?      %s" % os.path.basename(run_dir))
    print("  %d run(s) past retention" % len(expired))
    for run_dir, until in expired:
        print("      EXPIRED %-23s was due %s" % (os.path.basename(run_dir),
                                                  until))

    if not expired:
        print()
        print("Nothing to delete.")
        return 0
    if not args.force:
        print()
        print("DRY RUN: nothing was deleted. Re-run with --force to delete "
              "the %d expired run(s) above. Check first that every finding "
              "citing them has been delivered and accepted -- this removes "
              "the evidence behind them." % len(expired))
        return 0

    for run_dir, _ in expired:
        restrict(run_dir)
        shutil.rmtree(run_dir, ignore_errors=True)
        print("  deleted %s" % os.path.basename(run_dir))
    pointer = os.path.join(root, "latest-run.txt")
    if os.path.exists(pointer):
        with open(pointer) as fh:
            if not os.path.isdir(fh.read().strip()):
                os.remove(pointer)
    print()
    print("%d run(s) deleted." % len(expired))
    return 0


def cmd_verify(args):
    """Re-hash a run against its manifest. Reads only."""
    run_dir = _resolve_run(args, kind=args.kind)
    problems = EvidenceStore.verify(run_dir)
    print("run %s" % os.path.basename(run_dir))
    if not problems:
        print("  every artifact matches its recorded SHA-256.")
        return 0
    print("  %d integrity problem(s):" % len(problems))
    for problem in problems:
        print("    - %s" % problem)
    return 1


def cmd_commands(args):
    """Print the authoritative command table."""
    if args.json:
        print(json.dumps(COMMANDS, indent=2, sort_keys=True))
        return 0
    if args.markdown:
        print(command_table_markdown())
        return 0
    print("%-17s %-7s %-7s %-7s %s"
          % ("command", "sends", "writes", "scope", "summary"))
    print("%-17s %-7s %-7s %-7s %s"
          % ("-" * 17, "-" * 7, "-" * 7, "-" * 7, "-" * 40))
    for name in sorted(COMMANDS):
        spec = COMMANDS[name]
        print("%-17s %-7s %-7s %-7s %s"
              % (name,
                 "YES" if spec["sends_traffic"] else "no",
                 "yes" if spec["writes_files"] else "no",
                 "req" if spec["needs_scope"] else "-",
                 spec["summary"]))
    print()
    print("This table is generated from automation/cli/main.py:COMMANDS, "
          "which is the single authoritative statement. Every prose table in "
          "the repository is checked against it by the test suite.")
    return 0


def cmd_version(args):
    """Version, commit, environment and optional-dependency status.

    ENGINEERING IMPROVEMENT (review finding: "publish a version, commit
    identifier, supported environments, known limitations, and actual test
    results"). A report that cites a tool version is only useful if the tool
    can state its own, including which optional capabilities were actually
    available on the machine that produced the evidence.
    """
    from framework import environment as ENV
    info = ENV.describe()
    if args.json:
        print(json.dumps(info, indent=2, sort_keys=True))
        return 0
    print("apiscan-assessment %s" % info["version"])
    print("  commit       %s" % info["commit"])
    print("  python       %s" % info["python"])
    print("  platform     %s" % info["platform"])
    print("  supported    %s" % info["supported_environments"])
    print()
    print("capabilities on THIS host:")
    for name, status in sorted(info["capabilities"].items()):
        print("  %-14s %-14s %s" % (name, status["status"],
                                    status["effect_if_absent"]
                                    if not status["available"] else ""))
    print()
    print("known limitations: docs/KNOWN-LIMITATIONS.md")
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
    from framework.governance import modes as MODES

    p = argparse.ArgumentParser(
        prog="apiscan",
        description="Reusable API security assessment framework. "
                    "`apiscan commands` prints which subcommands send "
                    "traffic and which write files.")
    p.add_argument("--version", action="store_true",
                   help="print the version and exit")
    sub = p.add_subparsers(dest="command")

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

    def add_mode(sp):
        sp.add_argument("--mode", choices=list(MODES.ALL),
                        default=MODES.DEFAULT,
                        help="engagement mode (default: %s). %s"
                             % (MODES.DEFAULT,
                                " | ".join("%s: %s" % (n, MODES.MODES[n].summary)
                                           for n in MODES.ALL)))

    def add_limits(sp):
        sp.add_argument("--max-cases", type=int,
                        help="send at most this many cases (only ever "
                             "tightens the mode's ceiling)")
        sp.add_argument("--max-duration-s", type=float,
                        help="stop the run after this many seconds")
        sp.add_argument("--max-response-bytes", type=int,
                        help="refuse to download a response larger than this")
        sp.add_argument("--delay-s", type=float,
                        help="minimum seconds between requests")
        sp.add_argument("--stop-after-server-errors", type=int,
                        help="stop after this many consecutive 5xx or "
                             "transport failures")

    def add_run_selection(sp, kind="corpus"):
        sp.add_argument("--run", help="run id or directory to act on")
        sp.add_argument("--latest", action="store_true",
                        help="use the most recent run of kind %r instead of "
                             "naming one" % kind)

    sp = sub.add_parser("init-engagement",
                        help=COMMANDS["init-engagement"]["summary"])
    sp.add_argument("directory")
    sp.add_argument("--name", help="target name")
    sp.add_argument("--reference", help="engagement reference")
    sp.set_defaults(func=cmd_init_engagement)

    sp = sub.add_parser("validate", help=COMMANDS["validate"]["summary"])
    add_profile(sp)
    add_corpus(sp)
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("plan", help=COMMANDS["plan"]["summary"])
    add_profile(sp)
    add_corpus(sp)
    add_mode(sp)
    add_limits(sp)
    sp.add_argument("--direct", action="store_true",
                    help="plan a run that bypasses the proxy")
    sp.add_argument("--out", help="write the plan as JSON")
    sp.set_defaults(func=cmd_plan)

    sp = sub.add_parser("preflight", help=COMMANDS["preflight"]["summary"])
    add_profile(sp)
    add_mode(sp)
    add_limits(sp)
    sp.add_argument("--evidence", help="engagement evidence directory")
    sp.add_argument("--offline", action="store_true",
                    help="skip every networked check; needs no scope policy")
    sp.add_argument("--all", action="store_true",
                    help="run every check instead of stopping at the first "
                         "blocker")
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.set_defaults(func=cmd_preflight)

    sp = sub.add_parser("generate", help=COMMANDS["generate"]["summary"])
    add_profile(sp)
    add_corpus(sp)
    sp.add_argument("--out", help="write the corpus as JSON")
    sp.add_argument("--list", action="store_true", help="list every case")
    sp.add_argument("--show-skipped", type=int, default=10)
    sp.add_argument("--direct", action="store_true",
                    help="evaluate scope as though the run bypassed the proxy")
    sp.set_defaults(func=cmd_generate)

    sp = sub.add_parser("scan", help=COMMANDS["scan"]["summary"])
    add_profile(sp)
    add_corpus(sp)
    add_mode(sp)
    add_limits(sp)
    sp.add_argument("--evidence", required=True,
                    help="engagement evidence directory (outside the framework)")
    sp.add_argument("--direct", action="store_true",
                    help="bypass the proxy for this run")
    sp.add_argument("--note", help="operator note recorded in run metadata")
    sp.add_argument("--retention-days", type=int,
                    help="how long this evidence may be retained (recorded "
                         "in run metadata and enforced by `apiscan purge`)")
    sp.add_argument("--yes", action="store_true",
                    help="do not ask for confirmation of the test plan")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("reclassify", help=COMMANDS["reclassify"]["summary"])
    add_profile(sp)
    add_corpus(sp)
    sp.add_argument("--evidence", required=True)
    add_run_selection(sp)
    sp.add_argument("--verdict-policy", choices=["layered", "validation_strict"])
    sp.set_defaults(func=cmd_reclassify)

    sp = sub.add_parser("report", help=COMMANDS["report"]["summary"])
    sp.add_argument("--evidence", required=True)
    add_run_selection(sp)
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

    sp = sub.add_parser("capture", help=COMMANDS["capture"]["summary"])
    sp.add_argument("--evidence", required=True)
    add_run_selection(sp)
    sp.add_argument("--out", required=True)
    sp.add_argument("--ids", help="comma-separated case ids (default: every "
                                  "case with a finding or detector hit)")
    sp.set_defaults(func=cmd_capture)

    sp = sub.add_parser("redact", help=COMMANDS["redact"]["summary"])
    sp.add_argument("--evidence", required=True)
    add_run_selection(sp)
    sp.add_argument("--out", required=True,
                    help="directory for the redacted copy (outside the "
                         "framework; the raw run is not modified)")
    sp.add_argument("--profile",
                    help="engagement profile, so this engagement's own "
                         "credential values can be matched as literals")
    sp.add_argument("--lax-env", action="store_true")
    sp.add_argument("--kind", default="corpus",
                    help="kind of run to redact (default: corpus)")
    sp.add_argument("--pii", action="store_true",
                    help="also redact personal data shapes (e-mail "
                         "addresses, long digit runs)")
    sp.set_defaults(func=cmd_redact)

    sp = sub.add_parser("purge", help=COMMANDS["purge"]["summary"])
    sp.add_argument("--evidence", required=True)
    sp.add_argument("--force", action="store_true",
                    help="actually delete; without this nothing is removed")
    sp.add_argument("--as-of", help="evaluate retention as of this date "
                                    "(YYYY-MM-DD)")
    sp.set_defaults(func=cmd_purge)

    sp = sub.add_parser("verify", help=COMMANDS["verify"]["summary"])
    sp.add_argument("--evidence", required=True)
    add_run_selection(sp)
    sp.add_argument("--kind", default="corpus")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("tls-posture", help=COMMANDS["tls-posture"]["summary"])
    sp.add_argument("--profile", required=True)
    sp.add_argument("--scope", help="path to the engagement scope policy")
    sp.add_argument("--lax-env", action="store_true")
    add_mode(sp)
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
    sp.add_argument("--retention-days", type=int)
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_tls_posture)

    sp = sub.add_parser("snapshot", help=COMMANDS["snapshot"]["summary"])
    sp.add_argument("action", choices=["create", "list", "rollback"])
    sp.add_argument("--id", help="snapshot id to roll back to")
    sp.add_argument("--label", help="label for a new snapshot")
    sp.add_argument("--store", help="snapshot store directory")
    sp.set_defaults(func=cmd_snapshot)

    sp = sub.add_parser("commands", help=COMMANDS["commands"]["summary"])
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--markdown", action="store_true",
                    help="emit the table in the form the prose docs embed")
    sp.set_defaults(func=cmd_commands)

    sp = sub.add_parser("version", help=COMMANDS["version"]["summary"])
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_version)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False) and not getattr(args, "command", None):
        from framework import environment as ENV
        print("apiscan-assessment %s (commit %s)"
              % (ENV.VERSION, ENV.commit()))
        return 0
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
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
