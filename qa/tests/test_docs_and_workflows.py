"""Docs, workflows and the composite action must only use CLI forms the real parser accepts."""
import re
import shlex
import unittest
from pathlib import Path

import helpers  # noqa: F401
import aqa

ROOT = Path(__file__).resolve().parents[2]
COMMAND = re.compile(r'aqa\.py"?\s+((?:ci|review|run|doctor|contracts|smoke|pilot-report)\b[^`\n]*)')


SHELL_VALUES = {"AQA_POLICY_SOURCE": "base", "AQA_POLICY": ".qa/policy.json", "AQA_OUTPUT": ".qa/out"}


def expand(args: str) -> str:
    """Expand $VAR / ${VAR} the way the CI shell would, so choices= validators see real values."""
    return re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda m: SHELL_VALUES.get(m.group(1), "x"), args)


def commands(path: Path):
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for match in COMMAND.finditer(line):
            args = match.group(1).strip()
            if "..." in args or "<" in args:           # prose placeholders
                continue
            yield args


class DriftTests(unittest.TestCase):
    def test_every_documented_or_templated_command_parses(self):
        files = [ROOT / "action.yml", ROOT / ".github/workflows/qa-pr.yml", ROOT / "README.md", ROOT / "ARCHITECTURE.md",
                 ROOT / "CHANGELOG.md", *sorted((ROOT / "docs").glob("*.md")),
                 *sorted((ROOT / "examples").rglob("*.yml")), *sorted((ROOT / ".github/workflows").glob("*.yml"))]
        parser = aqa.build_parser()
        seen = 0
        for f in files:
            for args in commands(f):
                seen += 1
                with self.subTest(file=f.name, command=args):
                    try:
                        parser.parse_args(shlex.split(expand(args)))
                    except SystemExit as exc:
                        self.fail("unparseable (exit %s): aqa.py %s" % (exc.code, args))
        self.assertGreaterEqual(seen, 15, "extraction regex rotted: found only %d commands" % seen)

    def test_pipeline_b_templates_use_ci_and_never_ai_or_secrets(self):
        templates = [ROOT / ".github/workflows/qa-pr.yml", *sorted((ROOT / "examples/workflows").glob("pr-*.yml"))]
        self.assertEqual(len(templates), 6)
        for f in templates:
            text = f.read_text(encoding="utf-8")
            with self.subTest(file=f.name):
                self.assertRegex(text, r"aqa\.py\"?\s+ci\b")
                self.assertNotIn("review --agents", text)
                self.assertNotIn("pull_request_target", text.replace("never pull_request_target", ""))
                self.assertNotIn("secrets.", text)
                self.assertNotIn("--fix", text)
                self.assertIn("deterministic-qa", text)
                self.assertIn("persist-credentials: false", text)
                self.assertIn("AQA_POLICY_SOURCE: base", text)
                self.assertIn('git archive "$AQA_BASE_SHA" qa', text)
                self.assertIn('git cat-file -e "$AQA_BASE_SHA:qa/aqa.py"', text)
                self.assertIn('"$RUNNER_ROOT/qa/aqa.py" ci', text)

    def test_composite_action_defaults_to_trusted_base(self):
        self.assertIn('default: base', (ROOT / 'action.yml').read_text())

    def test_shipped_pr_actions_are_full_sha_pinned(self):
        templates = [ROOT / '.github/workflows/qa-pr.yml', *sorted((ROOT / 'examples/workflows').glob('pr-*.yml'))]
        for f in templates:
            for action in re.findall(r'uses:\s+([^\s#]+)', f.read_text()):
                self.assertRegex(action, r'^[-A-Za-z0-9_]+/[-A-Za-z0-9_]+@[a-f0-9]{40}$', (f, action))

    def test_stack_workflows_pair_with_stack_policies(self):
        for policy in (ROOT / "examples/policies").glob("*.json"):
            self.assertTrue((ROOT / "examples/workflows" / ("pr-%s.yml" % policy.stem)).exists(), policy.name)

    def test_documented_exit_codes_match_the_code(self):
        import aqa_core
        self.assertEqual((aqa_core.EXIT_PASSED, aqa_core.EXIT_FAILED, aqa_core.EXIT_INCOMPLETE, aqa_core.EXIT_ESCALATED), (0, 2, 3, 4))
        doc = (ROOT / "docs/CONTRACTS.md").read_text()
        for line in ("| 0 |", "| 2 |", "| 3 |", "| 4 |"):
            self.assertIn(line, doc)


if __name__ == "__main__":
    unittest.main()
