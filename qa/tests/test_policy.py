import json
import unittest
from datetime import date, timedelta
from pathlib import Path

import helpers  # noqa: F401
from helpers import Harness, commit_all, passing_check, policy_v2, setup_repo, sh
import aqa_policy as pol
import aqa_reviewers as rv


class ShippedProfilesTests(unittest.TestCase):
    def test_every_example_policy_and_the_starter_template_load_cleanly(self):
        root = Path(__file__).resolve().parents[2]
        files = sorted((root / "examples" / "policies").glob("*.json")) + [root / ".qa" / "policy.json"]
        self.assertGreaterEqual(len(files), 6)
        for f in files:
            with self.subTest(policy=f.name):
                policy, meta = pol.load_policy(root, str(f))
                self.assertEqual(meta["warnings"], [])
                self.assertEqual(policy["version"], 2)
                self.assertEqual(policy["ai_review"]["mode"], "advisory")
                self.assertFalse(policy["auto_fix"]["enabled"])               # never shipped enabled
                if f.parent.name == "policies":
                    covered = {c["category"] for c in policy["checks"] if c["required"]}
                    self.assertTrue(set(policy["required_categories"]) <= covered, f.name)

    def test_starter_template_is_unconfigured_on_purpose(self):
        root = Path(__file__).resolve().parents[2]
        policy, _ = pol.load_policy(root, str(root / ".qa" / "policy.json"))
        self.assertEqual(policy["checks"], [])


class PolicyValidationTests(unittest.TestCase):
    def norm(self, data):
        return pol.normalize_policy(data, Path("."))

    def test_v2_defaults(self):
        policy, warnings = self.norm({"version": 2, "checks": [{"name": "t", "category": "test", "argv": ["x"]}]})
        self.assertEqual(policy["required_categories"], ["test"])
        self.assertEqual(policy["ai_review"], {"mode": "advisory", "escalate_at": "major"})
        self.assertFalse(policy["auto_fix"]["enabled"])
        self.assertEqual(warnings, [])

    def test_strictness_rejects_typos_and_bad_values(self):
        bad = [
            {"version": 2, "required_categorys": ["test"]},
            {"version": 2, "checks": [{"name": "t", "argv": ["x"], "timout_seconds": 5}]},
            {"version": 2, "checks": [{"name": "t", "category": "tests", "argv": ["x"]}]},
            {"version": 2, "checks": [{"name": "t", "argv": ["x"]}, {"name": "t", "argv": ["y"]}]},
            {"version": 2, "checks": [{"name": "t", "argv": ["x"], "timeout_seconds": 99999}]},
            {"version": 2, "checks": [{"name": "t", "argv": ["x"], "env": {"API_TOKEN": "abc"}}]},
            {"version": 2, "checks": [{"name": "t", "argv": ["x"], "exit_codes": {"pass": [0], "fail": [0]}}]},
            {"version": 2, "checks": [{"name": "t", "argv": ["x"], "cwd": "../outside"}]},
            {"version": 2, "ai_review": {"mode": "loud"}},
            {"version": 2, "risk": {"agents": {"low": "everything"}}},
            {"version": 3}, {"checks": []}, [],
        ]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.norm(data)

    def test_v1_is_migrated_as_blocking_with_warning(self):
        policy, warnings = self.norm({"version": 1, "block_at": "minor", "checks": [{"name": "x", "argv": ["y"]}]})
        self.assertEqual(policy["ai_review"], {"mode": "blocking", "escalate_at": "minor"})
        self.assertEqual(policy["required_categories"], [])
        self.assertTrue(any("deprecated" in w for w in warnings))


class PolicySourceTests(Harness):
    def test_base_source_reads_the_trusted_policy_and_requires_it_to_exist(self):
        setup_repo(self.repo, policy_v2([passing_check("from-base")]))
        (self.repo / ".qa" / "policy.json").write_text(json.dumps(policy_v2([passing_check("from-pr")])))
        commit_all(self.repo)
        base = sh(self.repo, "git", "rev-parse", "main")
        policy, meta = pol.load_policy(self.repo, ".qa/policy.json", "base", base)
        self.assertEqual([c["name"] for c in policy["checks"]], ["from-base"])
        self.assertEqual(meta["source"], "base")
        with self.assertRaises(ValueError):
            pol.load_policy(self.repo, ".qa/nope.json", "base", base)

    def test_policy_diff_flags_weakening(self):
        base_policy = policy_v2([passing_check("unit"), passing_check("lint", "lint")])
        setup_repo(self.repo, base_policy)
        base = sh(self.repo, "git", "rev-parse", "main")
        path = self.repo / ".qa" / "policy.json"
        head, _ = pol.normalize_policy(policy_v2([passing_check("unit", required=False)], required_categories=[]), self.repo)
        diff = pol.policy_diff(head, self.repo, path, base)
        self.assertTrue(diff["weakened"])
        self.assertEqual(diff["removed_checks"], ["lint"])
        self.assertEqual(diff["optional_checks"], ["unit"])
        self.assertEqual(diff["removed_required_categories"], ["test"])
        added, _ = pol.normalize_policy(policy_v2([passing_check("unit"), passing_check("lint", "lint"), passing_check("sast", "sast")]), self.repo)
        diff = pol.policy_diff(added, self.repo, path, base)
        self.assertTrue(diff["changed"])
        self.assertFalse(diff["weakened"])


class ResolutionTests(Harness):
    def write(self, entries):
        (self.repo / ".qa").mkdir(exist_ok=True)
        (self.repo / ".qa" / "resolutions.json").write_text(json.dumps({"version": 1, "resolutions": entries}))

    def entry(self, **kw):
        base = {"fingerprint": "0123456789abcdef", "decision": "false_positive", "accepted_by": "@alice",
                "reason": "Verified safe by manual trace", "expires": (date.today() + timedelta(days=30)).isoformat()}
        base.update(kw)
        return base

    def test_active_expired_and_invalid(self):
        self.write([self.entry(), self.entry(fingerprint="fedcba9876543210", expires="2020-01-01")])
        active, warnings = pol.load_resolutions(self.repo)
        self.assertEqual(list(active), ["0123456789abcdef"])
        self.assertTrue(any("expired" in w for w in warnings))
        for bad in (self.entry(fingerprint="xyz"), self.entry(decision="fixed"), self.entry(reason="no"),
                    self.entry(accepted_by=" "), self.entry(expires=(date.today() + timedelta(days=400)).isoformat()),
                    self.entry(expires="soon")):
            self.write([bad])
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                pol.load_resolutions(self.repo)

    def test_fingerprint_is_line_insensitive_and_reviewer_specific(self):
        a = rv.make_finding("codex", "major", "a.py", 10, "SQL  injection", "e")
        b = rv.make_finding("codex", "major", "a.py", 99, "sql injection", "e")
        c = rv.make_finding("coderabbit", "major", "a.py", 10, "sql injection", "e")
        self.assertEqual(a["fingerprint"], b["fingerprint"])
        self.assertNotEqual(a["id"], b["id"])
        self.assertNotEqual(a["fingerprint"], c["fingerprint"])


class RiskTests(unittest.TestCase):
    def policy(self, **risk):
        return pol.normalize_policy({"version": 2, "risk": risk}, Path("."))[0]

    def test_tiers(self):
        p = self.policy()
        cases = [
            (["README.md", "docs/a.md"], {"README.md": 400, "docs/a.md": 400}, "low", "none"),
            (["src/app.py"], {"src/app.py": 5}, "low", "none"),
            (["src/app.py"], {"src/app.py": 60}, "medium", "coderabbit"),
            (["package-lock.json"], {"package-lock.json": 3}, "medium", "coderabbit"),
            (["src/auth/login.py"], {"src/auth/login.py": 2}, "high", "both"),
            ([".github/workflows/ci.yml"], {".github/workflows/ci.yml": 1}, "high", "both"),
            (["db/migrations/001.sql"], {"db/migrations/001.sql": 1}, "high", "both"),
            (["src/big.py"], {"src/big.py": 900}, "high", "both"),
            ([], {}, "low", "none"),
        ]
        for files, counts, tier, agents in cases:
            with self.subTest(files=files):
                result = pol.assess_risk(files, counts, p)
                self.assertEqual((result["tier"], result["agents"]), (tier, agents))

    def test_custom_rules_override_defaults_and_agents_are_configurable(self):
        p = self.policy(rules=[{"glob": "**/auth/**/*.md", "level": "low", "reason": "auth docs"}], agents={"low": "codex"})
        result = pol.assess_risk(["src/auth/README.md"], {"src/auth/README.md": 3}, p)
        self.assertEqual((result["tier"], result["agents"]), ("low", "codex"))


class GlobTests(unittest.TestCase):
    def test_globs(self):
        self.assertTrue(pol.glob_match("**/auth/**", "a/b/auth/c.py"))
        self.assertTrue(pol.glob_match("**/*.md", "README.md"))
        self.assertFalse(pol.glob_match("*.md", "docs/a.md"))
        self.assertTrue(pol.glob_match("src/**", "src/a/b.py"))
        self.assertTrue(pol.is_protected(".github/workflows/ci.yml"))
        self.assertTrue(pol.is_protected("qa/aqa.py"))
        self.assertFalse(pol.is_protected("src/qa.py"))

    def test_newlines_in_file_names_cannot_dodge_rules(self):
        # regression: '.' did not match newline and '$' matched before a trailing newline
        self.assertTrue(pol.is_protected(".github/workflows/x\n::y\n.yml"))
        self.assertTrue(pol.is_protected("qa/a\nb.py"))
        self.assertFalse(pol.glob_match("**/*.md", "evil.md\n"))
        self.assertEqual(pol.assess_risk(["src/auth/a\nb.py"], {"src/auth/a\nb.py": 1},
                                         pol.normalize_policy({"version": 2}, Path("."))[0])["tier"], "high")


if __name__ == "__main__":
    unittest.main()
