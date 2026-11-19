import json
import unittest
from datetime import date, timedelta
from pathlib import Path

import helpers
from helpers import (CODEX_CLEAN, CR_CLEAN, CR_FINDING_WHILE_CHANGED, PY, Harness, commit_all, fake_codex,
                     fake_coderabbit, passing_check, policy_v2, setup_repo, sh)
import aqa_reviewers as rv

FIX_DEMO = 'Path("demo.txt").write_text("baseline\\nfixed\\n"); out.write_text("fixed demo.txt")'


def codex_fixer(fix_code: str) -> str:
    return CODEX_CLEAN.replace('out.write_text("no-op")', fix_code)


def codex_finds(severity: str = "major") -> str:
    finding = ('{"severity": "%s", "file": "demo.txt", "line": 2, "title": "Codex finding", "evidence": "e", '
               '"suggested_fix": "f", "suggested_test": "t", "confidence": 0.9}' % severity)
    return CODEX_CLEAN.replace('"findings": []', '"findings": [%s]' % finding)


class AdvisorySemanticsTests(Harness):
    def both(self, *extra, **env):
        return self.review("--agents", "both", *extra, **env)

    def test_ai_findings_escalate_but_never_fail_the_gate(self):
        setup_repo(self.repo)
        fake_codex(self.bin)
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        proc = self.both()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = self.assert_valid_report()
        self.assertEqual(report["gate"]["status"], "passed")
        self.assertTrue(report["review"]["human_review_required"])
        escalation = [e for e in report["review"]["escalations"] if e["kind"] == "finding"][0]
        self.assertEqual(escalation["verdict"], "confirmed")           # fresh Codex verifier ran and is recorded
        self.assertIn("HUMAN REVIEW REQUIRED", proc.stdout)
        self.assertEqual(self.both("--strict-escalation").returncode, 4)

    def test_verifier_cannot_dismiss_a_finding(self):
        setup_repo(self.repo)
        fake_codex(self.bin, CODEX_CLEAN.replace('"verdict": "confirmed"', '"verdict": "likely_false_positive"'))
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        self.assertEqual(self.both().returncode, 0)
        finding = self.report()["rounds"][0]["findings"][0]
        self.assertEqual(finding["verification"]["verdict"], "likely_false_positive")
        self.assertEqual(finding["disposition"], "open")
        self.assertTrue(self.report()["review"]["human_review_required"])

    def test_blocking_mode_is_an_explicit_per_repo_opt_in(self):
        setup_repo(self.repo, policy_v2(ai_review={"mode": "blocking", "escalate_at": "major"}))
        fake_codex(self.bin)
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        self.assertEqual(self.both().returncode, 2)
        self.assertTrue(self.report()["gate"]["blocking_findings"])

    def test_v1_policy_keeps_blocking_behavior_and_warns(self):
        setup_repo(self.repo, {"version": 1, "block_at": "major", "checks": [passing_check("unit")]})
        fake_codex(self.bin)
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        proc = self.both()
        self.assertEqual(proc.returncode, 2)
        self.assertTrue(any("deprecated" in w for w in self.report()["warnings"]))

    def test_codex_finding_below_threshold_is_recorded_but_not_escalated(self):
        setup_repo(self.repo)
        fake_codex(self.bin, codex_finds("minor"))
        fake_coderabbit(self.bin)
        self.assertEqual(self.both().returncode, 0)
        report = self.report()
        self.assertEqual(len(report["rounds"][0]["findings"]), 1)
        self.assertFalse(report["review"]["human_review_required"])


class ReviewerGapTests(Harness):
    def test_missing_tool_is_a_visible_gap_not_a_clean_review(self):
        setup_repo(self.repo)
        fake_coderabbit(self.bin)                                   # codex deliberately absent
        proc = self.review("--agents", "both")
        self.assertEqual(proc.returncode, 0)                         # advisory: deterministic gate still passes
        report = self.assert_valid_report()
        self.assertEqual(report["rounds"][0]["reviews"]["codex"]["status"], "incomplete")
        self.assertEqual(report["review"]["coverage"], "partial")
        self.assertIn("review_gap", {e["kind"] for e in report["review"]["escalations"]})
        self.assertEqual(report["tools"]["codex"]["status"], "missing")

    def test_incomplete_review_blocks_in_blocking_mode(self):
        setup_repo(self.repo, policy_v2(ai_review={"mode": "blocking", "escalate_at": "major"}))
        fake_coderabbit(self.bin)
        self.assertEqual(self.review("--agents", "both").returncode, 3)

    def test_contract_violation_means_the_tool_is_never_invoked(self):
        setup_repo(self.repo)
        fake_codex(self.bin)
        fake_coderabbit(self.bin, version="coderabbit 0.0.1")
        self.review("--agents", "both")
        self.assertFalse(any(x.startswith("coderabbit review") for x in self.invoked()))
        gap = self.report()["rounds"][0]["reviews"]["coderabbit"]
        self.assertEqual(gap["status"], "incomplete")
        self.assertIn("contract violated", gap["note"])

    def test_malformed_tool_output_is_incomplete(self):
        setup_repo(self.repo)
        fake_codex(self.bin, 'out.write_text(json.dumps({"summary": "s", "findings": [{"severity": "high"}]}))')
        fake_coderabbit(self.bin, 'print(json.dumps({"type": "heartbeat"}))')
        self.assertEqual(self.review("--agents", "both").returncode, 0)
        reviews = self.report()["rounds"][0]["reviews"]
        self.assertEqual(reviews["codex"]["status"], "incomplete")
        self.assertIn("schema", reviews["codex"]["note"])
        self.assertEqual(reviews["coderabbit"]["status"], "incomplete")
        self.assertIn("complete", reviews["coderabbit"]["note"])

    def test_coderabbit_unreviewed_files_or_reuse_are_incomplete(self):
        setup_repo(self.repo)
        fake_codex(self.bin)
        fake_coderabbit(self.bin, CR_CLEAN.replace('"unreviewedFileCount": 0', '"unreviewedFileCount": 2'))
        self.review("--agents", "both")
        self.assertEqual(self.report()["rounds"][0]["reviews"]["coderabbit"]["status"], "incomplete")


class ResolutionTests(Harness):
    FP = rv.fingerprint("coderabbit", "demo.txt", "Needs fix")

    def write_resolution(self, expires):
        (self.repo / ".qa").mkdir(exist_ok=True)
        (self.repo / ".qa" / "resolutions.json").write_text(json.dumps({"version": 1, "resolutions": [{
            "fingerprint": self.FP, "decision": "false_positive", "accepted_by": "@alice",
            "reason": "Traced by hand; input is validated upstream", "expires": expires}]}))

    def test_human_resolution_suppresses_and_expiry_reopens(self):
        self.write_resolution((date.today() + timedelta(days=30)).isoformat())   # already approved on main
        setup_repo(self.repo)
        fake_codex(self.bin)
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        self.assertEqual(self.review("--agents", "both", "--strict-escalation").returncode, 0)
        report = self.assert_valid_report()
        finding = report["rounds"][0]["findings"][0]
        self.assertEqual(finding["disposition"], "suppressed")
        self.assertEqual(finding["resolution"]["accepted_by"], "@alice")     # the decision stays in the audit trail
        self.assertFalse(report["review"]["human_review_required"])
        self.assertEqual(report["review"]["escalations"], [])
        # the same decision, once expired, re-opens the finding
        self.write_resolution("2020-01-01")
        self.assertEqual(self.review("--agents", "both").returncode, 0)
        report = self.report()
        self.assertEqual(report["rounds"][0]["findings"][0]["disposition"], "open")
        self.assertTrue(any("expired" in w for w in report["warnings"]))
        self.assertIn("finding", {e["kind"] for e in report["review"]["escalations"]})

    def test_adding_or_editing_a_resolution_in_a_change_needs_codeowner_review(self):
        setup_repo(self.repo)
        fake_codex(self.bin)
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        self.write_resolution((date.today() + timedelta(days=30)).isoformat())   # introduced by THIS change
        commit_all(self.repo)
        self.assertEqual(self.review("--agents", "both").returncode, 0)
        kinds = {e["kind"] for e in self.report()["review"]["escalations"]}
        self.assertIn("protected_files_changed", kinds)
        self.assertNotIn("finding", kinds)                                       # suppressed, but the file change is flagged

    def test_malformed_resolutions_fail_closed(self):
        setup_repo(self.repo)
        fake_codex(self.bin)
        fake_coderabbit(self.bin)
        (self.repo / ".qa" / "resolutions.json").write_text('{"version": 1, "resolutions": [{"fingerprint": "nope"}]}')
        self.assertEqual(self.review("--agents", "both").returncode, 3)


class RiskSelectionTests(Harness):
    def run_auto(self, change, *extra):
        self.repo = self.tmp / ("r-" + change.replace("/", "_"))
        self.repo.mkdir()
        setup_repo(self.repo, change=change)
        self.fake_log.write_text("") if self.fake_log.exists() else None
        if self.fake_log.exists():
            self.fake_log.unlink()
        return self.review("--agents", "auto", *extra)

    def test_auto_selects_reviewers_by_risk_tier(self):
        fake_codex(self.bin)
        fake_coderabbit(self.bin)
        proc = self.run_auto("docs/readme.md")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.invoked(), [])
        report = self.report()
        self.assertEqual((report["risk"]["tier"], report["review"]["selected_agents"], report["review"]["coverage"]), ("low", "none", "none"))

        self.run_auto("package.json")
        self.assertEqual(self.report()["review"]["selected_agents"], "coderabbit")
        self.assertTrue(all(x.startswith("coderabbit") for x in self.invoked()))

        self.run_auto("src/auth/session.py")
        report = self.report()
        self.assertEqual((report["risk"]["tier"], report["review"]["selected_agents"]), ("high", "both"))
        self.assertTrue(any(x.startswith("codex exec") for x in self.invoked()))
        self.assertTrue(any(x.startswith("coderabbit review") for x in self.invoked()))
        self.assertIn("high_risk_change", {e["kind"] for e in report["review"]["escalations"]})


class FixLoopTests(Harness):
    FIX_POLICY = {"enabled": True, "max_files": 5, "allowed_paths": ["**"]}

    def fix(self, *extra, **env):
        return self.review("--agents", "both", "--fix", "--max-rounds", "2", *extra, **env)

    def test_policy_must_enable_auto_fix(self):
        setup_repo(self.repo)                                                  # auto_fix NOT enabled
        fake_codex(self.bin)
        fake_coderabbit(self.bin)
        proc = self.fix()
        self.assertEqual(proc.returncode, 3)
        self.assertIn("does not enable auto_fix", proc.stderr)

    def test_other_preconditions(self):
        setup_repo(self.repo, policy_v2(auto_fix=self.FIX_POLICY))             # enabled in the baseline policy too
        fake_codex(self.bin)
        fake_coderabbit(self.bin)
        self.assertEqual(self.review("--agents", "auto", "--fix").returncode, 3)         # needs explicit both
        self.assertIn("explicit --agents both", self.review("--agents", "auto", "--fix").stderr)
        self.assertIn("CI", self.fix(CI="true").stderr)                                  # forbidden in CI
        (self.repo / "demo.txt").write_text("dirty\n")
        self.assertIn("clean working tree", self.fix().stderr)
        sh(self.repo, "git", "checkout", "-q", "--", "demo.txt")
        sh(self.repo, "git", "switch", "-q", "main")
        self.assertIn("feature branch", self.fix().stderr)

    def test_bounded_fix_and_rereview_succeeds_inside_scope(self):
        setup_repo(self.repo, policy_v2(auto_fix=self.FIX_POLICY))
        fake_codex(self.bin, codex_fixer(FIX_DEMO))
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        proc = self.fix()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = self.assert_valid_report()
        self.assertEqual(len(report["rounds"]), 2)
        self.assertEqual(report["rounds"][0]["fix_result"]["touched_files"], ["demo.txt"])
        self.assertTrue(report["rounds"][0]["escalations"])                                  # round 1 had an escalation
        self.assertEqual(report["rounds"][1]["findings"], [])
        self.assertFalse(report["review"]["human_review_required"])
        self.assertEqual((self.repo / "demo.txt").read_text(), "baseline\nfixed\n")
        self.assertEqual(sh(self.repo, "git", "log", "--oneline").count("\n"), 1)         # nothing was committed by the tool

    def scope_case(self, fix_code, policy_fix):
        setup_repo(self.repo, policy_v2(auto_fix=policy_fix))
        fake_codex(self.bin, codex_fixer(fix_code))
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        proc = self.fix()
        report = self.assert_valid_report()
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertEqual(report["rounds"][0]["fix_result"]["status"], "violation")
        self.assertEqual(report["gate"]["status"], "incomplete")
        self.assertIn("fix_scope_violation", {e["kind"] for e in report["review"]["escalations"]})
        self.assertEqual(len(report["rounds"]), 1)                                          # loop stopped
        return report

    def test_fixer_touching_protected_files_is_a_violation_and_is_not_silently_reverted(self):
        code = ('Path(".github/workflows").mkdir(parents=True, exist_ok=True); '
                'Path(".github/workflows/evil.yml").write_text("on: push\\n"); out.write_text("x")')
        report = self.scope_case(code, self.FIX_POLICY)
        self.assertIn("protected", report["rounds"][0]["fix_result"]["violations"][0])
        self.assertTrue((self.repo / ".github/workflows/evil.yml").exists())               # left for the human to inspect

    def test_fixer_outside_allowed_paths_is_a_violation(self):
        self.scope_case(FIX_DEMO, {"enabled": True, "allowed_paths": ["src/**"]})

    def test_fixer_exceeding_max_files_is_a_violation(self):
        code = 'Path("demo.txt").write_text("baseline\\nfixed\\n"); Path("extra.txt").write_text("x"); out.write_text("x")'
        report = self.scope_case(code, {"enabled": True, "max_files": 1, "allowed_paths": ["**"]})
        self.assertIn("max_files", " ".join(report["rounds"][0]["fix_result"]["violations"]))

    def test_forbidden_paths_override_allowed_paths(self):
        self.scope_case(FIX_DEMO, {"enabled": True, "allowed_paths": ["**"], "forbidden_paths": ["demo.txt"]})

    def test_noop_fixer_stops_the_loop(self):
        setup_repo(self.repo, policy_v2(auto_fix=self.FIX_POLICY))
        fake_codex(self.bin)
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        self.assertEqual(self.fix().returncode, 0)
        self.assertEqual(len(self.report()["rounds"]), 1)

    def test_recurring_finding_after_a_fix_is_escalated_as_ineffective(self):
        setup_repo(self.repo, policy_v2(auto_fix=self.FIX_POLICY))
        fake_codex(self.bin, codex_fixer('Path("demo.txt").write_text("baseline\\nchange\\nmore\\n"); out.write_text("x")'))
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        self.fix()
        report = self.report()
        self.assertEqual(len(report["rounds"]), 2)
        self.assertTrue(report["rounds"][1]["findings"][0]["recurring"])
        self.assertIn("fix_ineffective", {e["kind"] for e in report["review"]["escalations"]})


if __name__ == "__main__":
    unittest.main()
