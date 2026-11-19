import json
import subprocess
import unittest
from pathlib import Path

import helpers
from helpers import (CR_FINDING_WHILE_CHANGED, PY, SCRIPT, Harness, fake_codex, fake_coderabbit, passing_check,
                     policy_v2, setup_repo, sh)
import aqa_reviewers as rv


class PilotReportTests(Harness):
    def make(self, name, policy=None):
        repo = self.tmp / name
        repo.mkdir()
        (repo / "unique.txt").write_text(name)          # distinct history => distinct HEAD SHA (expected-labels key)
        setup_repo(repo, policy)
        return repo

    def run_in(self, repo, out, *args):
        return subprocess.run([PY, str(SCRIPT), *args, "--repo", str(repo), "--base", "main", "--out", str(out)],
                              capture_output=True, text=True, env=self.env(), cwd=repo)

    def test_aggregates_runs_into_the_five_pilot_metrics(self):
        fake_codex(self.bin)
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        good = self.make("good")
        bad = self.make("bad", policy_v2([{"name": "unit", "category": "test", "argv": [PY, "-c", "raise SystemExit(1)"]}]))
        reviewed = self.make("reviewed")
        outs = self.tmp / "evidence"
        self.assertEqual(self.run_in(good, outs / "good", "ci").returncode, 0)
        self.assertEqual(self.run_in(bad, outs / "bad", "ci").returncode, 2)
        self.assertEqual(self.run_in(reviewed, outs / "reviewed", "review", "--agents", "both").returncode, 0)

        head = {n: sh(r, "git", "rev-parse", "HEAD") for n, r in (("good", good), ("bad", bad), ("reviewed", reviewed))}
        expected = self.tmp / "expected.json"
        expected.write_text(json.dumps({head["good"][:12]: "passed", head["bad"][:12]: "failed", head["reviewed"][:12]: "passed"}))
        triage = self.tmp / "triage.json"
        triage.write_text(json.dumps({rv.fingerprint("coderabbit", "demo.txt", "Needs fix"): "actionable"}))

        proc = self.aqa("pilot-report", str(outs), "--expected", str(expected), "--triage", str(triage), "--json", env=self.env())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        summary = json.loads(proc.stdout)
        self.assertEqual(summary["runs"], 3)
        self.assertEqual(summary["gate_counts"], {"passed": 2, "failed": 1})
        self.assertEqual(summary["classification"]["accuracy"], 1.0)
        self.assertEqual(summary["cli_contracts"]["coderabbit"], {"ok": 1})
        self.assertEqual(summary["review_usefulness"]["triage"]["coderabbit"]["precision"], 1.0)
        self.assertEqual(summary["review_usefulness"]["reviewer_completion"]["coderabbit"], {"completed": 1})
        self.assertIsNotNone(summary["latency_seconds"]["run_p50"])
        self.assertEqual(summary["fix_safety"], {"fix_attempts": 0, "scope_violations": 0})
        self.assertIn("not measured", summary["cost"])
        self.assertIn("finding", summary["escalations_by_kind"])

        # the metric must be able to say "wrong": a mislabeled expectation lowers accuracy
        expected.write_text(json.dumps({head["good"][:12]: "failed", head["bad"][:12]: "failed"}))
        wrong = json.loads(self.aqa("pilot-report", str(outs), "--expected", str(expected), "--json", env=self.env()).stdout)
        self.assertEqual(wrong["classification"]["accuracy"], 0.5)

        text = self.aqa("pilot-report", str(outs), env=self.env()).stdout
        self.assertIn("## 1. CLI compatibility", text)
        self.assertIn("## 5. Fix safety", text)

    def test_precision_denominator_excludes_duplicates_and_includes_wontfix(self):
        from aqa_report import pilot_summary
        target = self.tmp / 'evidence'
        target.mkdir()
        def finding(fingerprint):
            return {'reviewer':'codex','severity':'major','fingerprint':fingerprint}
        report = {'schema_version':2, 'gate':{'status':'passed','reasons':[]},
                  'duration_seconds':1, 'head_sha':'abcdef', 'tools':{},
                  'review':{'escalations':[]},
                  'rounds':[{'checks':[], 'reviews':{}, 'findings':[
                      finding('good'),finding('risk'),finding('bad'),finding('duplicate')]}]}
        (target/'report.json').write_text(json.dumps(report))
        summary = pilot_summary([target], {}, {'good':'actionable', 'risk':'wontfix',
                                                 'bad':'false_positive','duplicate':'duplicate'})
        triage = summary['review_usefulness']['triage']['codex']
        self.assertEqual((triage['labeled'],triage['eligible'],triage['duplicates_excluded']), (4,3,1))
        self.assertEqual(triage['accepted_risk'],1)
        self.assertEqual(triage['precision'],0.667)

    def test_unreadable_reports_are_counted_not_ignored(self):
        (self.tmp / "junk").mkdir()
        (self.tmp / "junk" / "report.json").write_text("{nope")
        summary = json.loads(self.aqa("pilot-report", str(self.tmp / "junk"), "--json", env=self.env()).stdout)
        self.assertEqual((summary["runs"], summary["unreadable_reports"]), (0, 1))


if __name__ == "__main__":
    unittest.main()
