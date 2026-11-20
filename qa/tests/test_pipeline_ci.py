import json
import subprocess
import sys
import time
import unittest

from helpers import (
    PY,
    QA,
    Harness,
    commit_all,
    passing_check,
    policy_v2,
    setup_repo,
    sh,
)


class DeterministicGateTests(Harness):
    def test_passes_with_a_required_test_check_and_report_is_schema_valid(self):
        setup_repo(self.repo)
        proc = self.ci()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = self.assert_valid_report()
        self.assertEqual(report["gate"]["status"], "passed")
        self.assertEqual(report["pipeline"], "ci")
        self.assertEqual(report["review"]["coverage"], "none")
        check = report["rounds"][0]["checks"][1]
        self.assertEqual((check["name"], check["category"], check["status"]), ("unit", "test", "passed"))
        self.assertEqual(len(check["log_sha256"]), 64)

    def test_no_checks_is_incomplete(self):
        setup_repo(self.repo, policy_v2([], required_categories=[]))
        self.assertEqual(self.ci().returncode, 3)
        self.assertEqual(self.assert_valid_report()["gate"]["status"], "incomplete")

    def test_required_category_without_a_covering_check_is_incomplete_not_green(self):
        setup_repo(self.repo, policy_v2([passing_check("ruff", "lint")], required_categories=["test", "lint"]))
        proc = self.ci()
        self.assertEqual(proc.returncode, 3)
        self.assertIn("coverage:test", json.dumps(self.report()["gate"]["reasons"]))
        # an OPTIONAL test check does not satisfy the requirement either
        (self.repo / ".qa" / "policy.json").write_text(json.dumps(policy_v2(
            [passing_check("ruff", "lint"), passing_check("t", "test", required=False)], required_categories=["test"])))
        self.assertEqual(self.ci().returncode, 3)

    def test_failing_check_fails_gate(self):
        setup_repo(self.repo, policy_v2([{"name": "unit", "category": "test", "argv": [PY, "-c", "raise SystemExit(1)"]}]))
        self.assertEqual(self.ci().returncode, 2)

    def test_missing_executable_required_incomplete_optional_skipped(self):
        setup_repo(self.repo, policy_v2([passing_check(), {"name": "ghost", "category": "lint", "argv": ["no-such-tool-xyz"]}]))
        self.assertEqual(self.ci().returncode, 3)
        (self.repo / ".qa" / "policy.json").write_text(json.dumps(policy_v2(
            [passing_check(), {"name": "ghost", "category": "lint", "argv": ["no-such-tool-xyz"], "required": False}])))
        self.assertEqual(self.ci().returncode, 0)
        statuses = {c["name"]: c["status"] for c in self.report()["rounds"][0]["checks"]}
        self.assertEqual(statuses["ghost"], "skipped")
        # a skipped optional scanner must be VISIBLE, not silent assurance
        self.assertTrue(any("SKIPPED" in w and "ghost" in w for w in self.report()["warnings"]))
        summary = self.tmp / "summary.md"
        self.ci(GITHUB_STEP_SUMMARY=str(summary))
        self.assertIn("ghost", summary.read_text())

    def test_scanner_exit_code_mapping_distinguishes_findings_from_tool_errors(self):
        def run_with(code):
            check = {"name": "scan", "category": "secrets", "exit_codes": {"pass": [0], "fail": [1]},
                     "argv": [PY, "-c", f"raise SystemExit({code})"]}
            (self.repo / ".qa" / "policy.json").write_text(json.dumps(policy_v2([passing_check(), check])))
            return self.ci().returncode
        setup_repo(self.repo)
        self.assertEqual(run_with(0), 0)
        self.assertEqual(run_with(1), 2)      # scanner says "found something": failed
        self.assertEqual(run_with(7), 3)      # scanner crashed: incomplete, never a silent pass or false fail

    def test_timeout_is_incomplete_and_kills_the_process_tree_fast(self):
        pidfile = self.tmp / "pid"
        script = ("import subprocess,sys,time;p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                  f"open({str(pidfile)!r},'w').write(str(p.pid));time.sleep(60)")   # hermetic PATH has no `sleep`
        setup_repo(self.repo, policy_v2([passing_check(), {"name": "hang", "category": "other", "argv": [PY, "-c", script], "timeout_seconds": 2}]))
        started = time.monotonic()
        proc = self.ci()
        self.assertEqual(proc.returncode, 3)
        self.assertLess(time.monotonic() - started, 30)
        from test_core import process_alive
        time.sleep(0.3)
        self.assertFalse(process_alive(int(pidfile.read_text())))
        self.assertIn("timed out", json.dumps(self.report()["gate"]["reasons"]))

    def test_whitespace_errors_in_the_diff_fail_via_builtin_check(self):
        setup_repo(self.repo)
        (self.repo / "demo.txt").write_text("baseline\nchange \n")
        commit_all(self.repo)
        self.assertEqual(self.ci().returncode, 2)

    def test_usage_errors_and_bad_inputs_are_incomplete_never_failed(self):
        setup_repo(self.repo)
        self.assertEqual(self.ci("--bogus-flag").returncode, 3)
        self.assertEqual(self.ci("--policy-sour", "base").returncode, 3)      # abbreviations are rejected, not guessed
        self.assertEqual(self.aqa("ci", "--repo", str(self.tmp), "--base", "main").returncode, 3)   # not a repo
        self.assertEqual(self.aqa("ci", "--repo", str(self.repo), "--base", "no-such-ref").returncode, 3)
        (self.repo / ".qa" / "policy.json").write_text("{not json")
        self.assertEqual(self.ci().returncode, 3)


class SecurityBoundaryTests(Harness):
    SECRET = "sk-" + "q" * 32

    def test_provider_secrets_are_not_visible_to_repository_commands(self):
        probe = "import os;print('SEEN' if os.environ.get('OPENAI_API_KEY') else 'HIDDEN')"
        setup_repo(self.repo, policy_v2([{"name": "unit", "category": "test", "argv": [PY, "-c", probe]}]))
        self.assertEqual(self.ci(OPENAI_API_KEY=self.SECRET, GITHUB_TOKEN="ghp_" + "t" * 36).returncode, 0)
        log = (self.repo / ".qa/out/round-01/check-01-unit.log").read_text()
        self.assertIn("HIDDEN", log)

    def test_explicit_passthrough_is_honored_and_still_redacted_in_evidence(self):
        probe = "import os;print('value=' + os.environ['PROJECT_API_KEY'])"
        setup_repo(self.repo, policy_v2([{"name": "unit", "category": "test", "argv": [PY, "-c", probe],
                                          "env_passthrough": ["PROJECT_API_KEY"]}]))
        self.assertEqual(self.ci(PROJECT_API_KEY="plain-secret-value-123").returncode, 0)
        out = self.repo / ".qa" / "out"
        blob = "".join(p.read_text() for p in out.rglob("*") if p.is_file())
        self.assertNotIn("plain-secret-value-123", blob)
        self.assertIn("[REDACTED]", (out / "round-01/check-01-unit.log").read_text())
        self.assertTrue(any("secret-like" in w for w in self.report()["warnings"]))

    def test_token_shaped_output_is_redacted_from_logs_and_report(self):
        leak = "print('token ' + 'ghp_' + 'Z' * 36)"
        setup_repo(self.repo, policy_v2([{"name": "unit", "category": "test", "argv": [PY, "-c", leak]}]))
        self.assertEqual(self.ci().returncode, 0)
        blob = "".join(p.read_text() for p in (self.repo / ".qa" / "out").rglob("*") if p.is_file())
        self.assertNotIn("Z" * 36, blob)

    def test_ci_pipeline_never_loads_ai_adapters(self):
        setup_repo(self.repo)
        code = (f"import sys; sys.path.insert(0, {str(QA)!r}); import aqa;"
                f"rc = aqa.main(['ci','--repo',{str(self.repo)!r},'--base','main']);"
                "print('LOADED' if 'aqa_reviewers' in sys.modules else 'CLEAN'); sys.exit(rc)")
        proc = subprocess.run([PY, "-c", code], capture_output=True, text=True, env=self.env(), check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("CLEAN", proc.stdout)
        self.assertEqual(self.invoked(), [])

    @unittest.skipIf(sys.platform == "win32", "Windows filesystems do not allow newlines or colons in filenames")
    def test_github_annotations_cannot_be_injected_through_file_names(self):
        evil = ".github/workflows/x\n::set-output name=pwned::1\n.yml"
        setup_repo(self.repo, change=evil)
        summary = self.tmp / "summary.md"
        proc = self.ci(GITHUB_ACTIONS="true", GITHUB_STEP_SUMMARY=str(summary))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        commands = [l for l in proc.stdout.splitlines() if l.startswith("::")]
        self.assertTrue(commands)
        for line in commands:
            self.assertRegex(line, r"^::(warning|error) title=")
        self.assertNotIn("\n::set-output", proc.stdout)
        self.assertIn("Adversarial QA", summary.read_text())


class TrustAndEscalationTests(Harness):
    """Advisory signals: they never fail the gate, but a human must see them."""

    def kinds(self):
        return {e["kind"] for e in self.report()["review"]["escalations"]}

    def test_low_risk_change_needs_no_human_flag(self):
        setup_repo(self.repo, change="docs/notes.md")
        self.assertEqual(self.ci().returncode, 0)
        report = self.assert_valid_report()
        self.assertEqual(report["risk"]["tier"], "low")
        self.assertFalse(report["review"]["human_review_required"])

    def test_high_risk_and_protected_file_changes_escalate_without_failing(self):
        setup_repo(self.repo, change="src/auth/login.py")
        self.assertEqual(self.ci().returncode, 0)
        self.assertEqual(self.kinds(), {"high_risk_change"})
        sh(self.repo, "git", "switch", "-qc", "second", "main")
        (self.repo / ".github/workflows").mkdir(parents=True)
        (self.repo / ".github/workflows/ci.yml").write_text("name: x\n")
        commit_all(self.repo)
        self.assertEqual(self.ci().returncode, 0)
        self.assertIn("protected_files_changed", self.kinds())

    def test_pr_cannot_weaken_its_own_gate_when_policy_source_is_base(self):
        failing = policy_v2([{"name": "unit", "category": "test", "argv": [PY, "-c", "raise SystemExit(1)"]}])
        setup_repo(self.repo, failing)
        (self.repo / ".qa" / "policy.json").write_text(json.dumps(policy_v2([passing_check("unit")])))   # PR "fixes" the gate
        commit_all(self.repo)
        proc = self.ci()                                                    # default: worktree policy
        self.assertEqual(proc.returncode, 0)
        self.assertIn("protected_files_changed", self.kinds())
        proc = self.ci("--policy-source", "base")                           # strict: trusted base policy decides
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(self.report()["policy"]["source"], "base")
        self.assertIn("protected_files_changed", self.kinds())

    def test_removing_a_check_is_reported_as_policy_weakening(self):
        setup_repo(self.repo, policy_v2([passing_check("unit"), passing_check("lint", "lint")]))
        (self.repo / ".qa" / "policy.json").write_text(json.dumps(policy_v2([passing_check("unit")])))
        commit_all(self.repo)
        self.assertEqual(self.ci().returncode, 0)
        self.assertIn("policy_weakened", self.kinds())
        self.assertEqual(self.report()["policy_changes"]["removed_checks"], ["lint"])


class DeprecatedRunAliasTests(Harness):
    def test_run_agents_none_maps_to_ci_with_warning(self):
        setup_repo(self.repo)
        proc = self.aqa("run", "--repo", str(self.repo), "--base", "main", "--agents", "none", env=self.env())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("deprecated", proc.stderr)
        self.assertEqual(self.report()["pipeline"], "ci")


if __name__ == "__main__":
    unittest.main()
