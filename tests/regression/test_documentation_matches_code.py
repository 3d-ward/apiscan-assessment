"""The prose must not contradict the code.

ENGINEERING IMPROVEMENT (review finding 3: "I found contradictory guidance:
SKILL.md acknowledges that preflight sends traffic, while CLAUDE.md says only
two other commands do" and "keep one authoritative workflow and derive the
other guides from it to reduce contradictions").

The contradiction was not an oversight that careful proofreading would have
caught. The same table was written out by hand in four documents, so drift was
only a matter of time, and the direction of the drift was dangerous: a reader
following CLAUDE.md believed a readiness check was free.

The fix is mechanical. ``automation/cli/main.py:COMMANDS`` is the single
declaration, ``apiscan commands --markdown`` renders it, every document embeds
that rendering between markers, and this file regenerates and compares. A
document that falls behind fails the build with the command to fix it.
"""
import os
import re
import unittest

from tests.support import ROOT  # noqa: F401
from automation.cli.main import (COMMANDS, GENERATED_TABLE_BEGIN,
                                 GENERATED_TABLE_END, TRAFFIC_COMMANDS,
                                 build_parser, command_table_markdown)

#: Every document that states which commands send traffic.
DOCS_WITH_TABLE = (
    "docs/WORKFLOW.md",
    "CLAUDE.md",
    "README.md",
    os.path.join("skills", "apiscan-assessment", "SKILL.md"),
)

ALL_DOCS = DOCS_WITH_TABLE + (
    "docs/KNOWN-LIMITATIONS.md",
    "RELEASE.md",
)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def embedded_table(text):
    start = text.find(GENERATED_TABLE_BEGIN)
    end = text.find(GENERATED_TABLE_END)
    if start < 0 or end < 0:
        return None
    return text[start:end + len(GENERATED_TABLE_END)]


class TestCommandTableIsGenerated(unittest.TestCase):
    def test_every_document_embeds_the_generated_table(self):
        expected = command_table_markdown()
        for rel in DOCS_WITH_TABLE:
            found = embedded_table(read(rel))
            self.assertIsNotNone(
                found, "%s does not embed the generated command table" % rel)
            self.assertEqual(
                found, expected,
                "%s has drifted from the code. Regenerate it:\n"
                "  ./apiscan commands --markdown\n"
                "and replace the block between the BEGIN/END markers." % rel)

    def test_the_table_covers_every_subcommand_the_parser_offers(self):
        """A command the parser accepts but the table omits would be a command
        whose traffic behaviour is undocumented."""
        parser = build_parser()
        actions = [a for a in parser._subparsers._group_actions
                   if hasattr(a, "choices")]
        self.assertTrue(actions)
        offered = set()
        for action in actions:
            offered.update(action.choices)
        self.assertEqual(offered, set(COMMANDS),
                         "the parser and COMMANDS disagree about which "
                         "subcommands exist")

    def test_exactly_the_sending_commands_are_marked_as_sending(self):
        self.assertEqual(TRAFFIC_COMMANDS,
                         ["preflight", "scan", "tls-posture"],
                         "if this changed deliberately, the docs' prose about "
                         "which commands send traffic needs updating too")


class TestNoDocumentContradictsTheCode(unittest.TestCase):
    #: The specific wrong claim the review found, plus the shapes it would
    #: come back in. "two commands send traffic" was true of an earlier
    #: design and survived into a document after preflight gained its probes.
    WRONG_CLAIMS = (
        re.compile(r"(?i)\b(two|2)\s+commands\s+(that\s+)?send"),
        re.compile(r"(?i)only\s+(two|2)\s+commands"),
        re.compile(r"(?i)preflight[^.\n]{0,40}\bsends?\s+nothing"),
        re.compile(r"(?i)\bpreflight\b[^.\n]{0,30}\bnever\s+sends?"),
    )

    def test_no_document_claims_only_two_commands_send_traffic(self):
        for rel in ALL_DOCS:
            text = read(rel)
            for pattern in self.WRONG_CLAIMS:
                match = pattern.search(text)
                self.assertIsNone(
                    match,
                    "%s contains a claim contradicted by the code (%r). "
                    "Three commands send traffic: %s."
                    % (rel, match.group(0) if match else "",
                       ", ".join(TRAFFIC_COMMANDS)))

    def test_the_documented_default_deny_matches_the_code(self):
        from framework.governance.scope import DEFAULT_DENY
        for rel in ("CLAUDE.md", os.path.join("skills", "apiscan-assessment",
                                              "SKILL.md")):
            text = read(rel)
            for klass in DEFAULT_DENY:
                self.assertIn(
                    klass, text,
                    "%s does not mention default-denied class %r" % (rel, klass))

    def test_the_documented_modes_match_the_code(self):
        from framework.governance import modes as M
        for rel in DOCS_WITH_TABLE:
            text = read(rel)
            for name in M.ALL:
                self.assertIn(name, text,
                              "%s does not mention mode %r" % (rel, name))

    def test_the_workflow_document_declares_itself_authoritative(self):
        text = read("docs/WORKFLOW.md")
        self.assertIn("authoritative", text.lower())

    def test_the_other_documents_defer_to_the_workflow(self):
        for rel in ("CLAUDE.md", "README.md",
                    os.path.join("skills", "apiscan-assessment",
                                 "SKILL.md")):
            self.assertIn("WORKFLOW.md", read(rel),
                          "%s does not point at the authoritative workflow"
                          % rel)


class TestTheSkillActivatesOnTheTask(unittest.TestCase):
    """REVIEW 3. "Activate based on the user's task; the mere presence of a
    profile file should not trigger an assessment workflow."
    """

    def frontmatter(self):
        text = read(os.path.join("skills", "apiscan-assessment", "SKILL.md"))
        match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        self.assertIsNotNone(match, "the skill has no YAML frontmatter")
        return match.group(1)

    def test_the_description_does_not_trigger_on_a_file_being_present(self):
        description = self.frontmatter()
        self.assertNotIn("is present", description,
                         "the skill still activates on the presence of a "
                         "file rather than on the user's request")
        self.assertIn("asks", description.lower())

    def test_the_skill_says_what_never_to_do(self):
        text = read(os.path.join("skills", "apiscan-assessment", "SKILL.md"))
        for rule in ("Never invent an authorisation",
                     "Never widen",
                     "Never set `tls_verify.mode` to `insecure`"):
            self.assertIn(rule, text, rule)

    def test_the_skill_states_the_untrusted_data_rule(self):
        text = read(os.path.join("skills", "apiscan-assessment", "SKILL.md"))
        self.assertIn("untrusted", text.lower())
        self.assertIn("never as instructions", text.lower())

    def test_the_skill_requires_explicit_run_ids(self):
        text = read(os.path.join("skills", "apiscan-assessment", "SKILL.md"))
        self.assertIn("--run", text)
        self.assertIn("--latest", text)


class TestReleaseDocumentationExists(unittest.TestCase):
    """REVIEW 5. "Establish a repeatable release process."""

    def test_the_release_process_is_written_down(self):
        text = read("RELEASE.md")
        for topic in ("version", "commit", "supported", "known limitations",
                      "test results"):
            self.assertIn(topic, text.lower(), topic)

    def test_a_second_maintainer_reviews_sensitive_areas(self):
        """"Have another maintainer review changes affecting scope,
        credentials, transport, or verdicts."""
        text = read("RELEASE.md").lower()
        for area in ("scope", "credential", "transport", "verdict"):
            self.assertIn(area, text, area)

    def test_continuous_integration_covers_the_supported_matrix(self):
        path = os.path.join(ROOT, ".github", "workflows", "ci.yml")
        self.assertTrue(os.path.exists(path), "no CI workflow")
        with open(path) as fh:
            text = fh.read()
        for platform in ("ubuntu", "macos", "windows"):
            self.assertIn(platform, text, platform)
        from framework import environment as ENV
        oldest = "3.%d" % ENV.SUPPORTED_PYTHON[1]
        self.assertIn(oldest, text,
                      "CI does not test the oldest supported Python (%s)"
                      % oldest)


if __name__ == "__main__":
    unittest.main()
