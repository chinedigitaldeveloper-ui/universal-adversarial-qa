"""Regression tests for the three review findings and base-runner CI isolation."""
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import aqa
import aqa_core as core
import aqa_reviewers as reviewers
import helpers
from helpers import (
    PY,
    QA,
    Harness,
    commit_all,
    fake_coderabbit,
    passing_check,
    policy_v2,
    setup_repo,
    sh,
)


class CheckCrashTests(Harness):
    def test_direct_signal_exit_is_incomplete_with_a_clear_reason(self):
        if os.name != 'posix':
            self.skipTest('POSIX negative signal codes')
        policy = policy_v2([{"name": "crashing-test", "category": "test",
                            "argv": [PY, "-c", "import os,signal;os.kill(os.getpid(),signal.SIGKILL)"]}])
        setup_repo(self.repo, policy)
        result = self.ci()
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        check = self.report()["rounds"][0]["checks"][1]
        self.assertEqual(check["status"], "incomplete")
        self.assertEqual(check["exit_code"], -9)
        self.assertIn('signal 9', check["reason"])

    def test_classify_exit_distinguishes_crashes_from_real_assertion_failures(self):
        codes = {"pass": [0], "fail": None}
        for signal_code in (-9, -11, -15):
            self.assertEqual(aqa.classify_exit(signal_code, codes), "incomplete")
        self.assertEqual(aqa.classify_exit(1, codes), "failed")
        self.assertEqual(aqa.classify_exit(0, codes), "passed")


class BoundedOutputTests(unittest.TestCase):
    def test_complete_output_is_not_tailed(self):
        res = core.run_process_bounded([PY, '-c', 'print("X"*50000)'], Path('.'),
                                       seconds=10, stdout_limit=100000)
        self.assertFalse(res['truncated'])
        self.assertEqual(len(res['stdout'].strip()), 50000)
        self.assertEqual(res['code'], 0)

    def test_over_limit_is_bounded_and_never_successful(self):
        res = core.run_process_bounded([PY, '-c', 'print("X"*500000)'], Path('.'),
                                       seconds=10, stdout_limit=2048)
        self.assertTrue(res['truncated'])
        self.assertTrue(res['output_limit_exceeded'])
        self.assertLessEqual(len(res['stdout']), 2048)
        self.assertNotEqual(res['code'], 0)

    def test_stderr_limit_causes_incomplete_capture(self):
        res = core.run_process_bounded([PY, '-c', 'import sys;sys.stderr.write("X"*100000)'], Path('.'),
                                       seconds=10, stderr_limit=1024)
        self.assertTrue(res['truncated'])
        self.assertTrue(res['output_limit_exceeded'])
        self.assertLessEqual(len(res['stderr']), 1024)


class CodeRabbitCompleteStreamTests(Harness):
    def setUp(self):
        super().setUp()
        setup_repo(self.repo)

    def direct_review(self, limit=reviewers.MAX_REVIEW_STREAM_BYTES):
        with mock.patch.dict(os.environ, self.env()):
            # Real adapter path, fake CLI: verifies parsing, capture, consistency.
            return reviewers.coderabbit_review(self.repo, sh(self.repo, 'git', 'rev-parse', 'main'),
                                               'major', self.tmp/'cr-review', ['demo.txt'],
                                               timeout=15, stream_limit_bytes=limit)

    def test_malformed_line_never_yields_a_completed_review(self):
        fake_coderabbit(self.bin, 'print("not-json");\n' + helpers.CR_CLEAN)
        report = self.direct_review()
        self.assertEqual(report['status'], 'incomplete')
        self.assertEqual(report['non_json_lines'], 1)
        self.assertIn('non-JSON', report['note'])

    def test_many_findings_preserved_beyond_old_30000_character_tail(self):
        body = ("for i in range(500):\n"
                " print(json.dumps({'type':'finding','severity':'minor','fileName':'src/demo.py',"
                "                   'title':'Issue %03d'%i,'comment':'evidence-'+str(i)}))\n"
                + helpers.CR_CLEAN)
        fake_coderabbit(self.bin, body)
        report = self.direct_review()
        self.assertEqual(report['status'], 'completed', report)
        self.assertEqual(len(report['findings']), 500)
        self.assertEqual(report['findings'][0]['title'], 'Issue 000')
        self.assertEqual(report['findings'][-1]['title'], 'Issue 499')
        self.assertFalse(report['output_truncated'])
        self.assertGreater((self.tmp/'cr-review'/'coderabbit.ndjson').stat().st_size, 30000)

    def test_review_exceeding_output_limit_is_incomplete(self):
        fake_coderabbit(self.bin, 'print("x"*40000);\n' + helpers.CR_CLEAN)
        report = self.direct_review(limit=1024)
        self.assertEqual(report['status'], 'incomplete')
        self.assertTrue(report['output_limit_exceeded'])
        self.assertTrue(report['output_truncated'])
        self.assertIn('capture limit', report['note'])

    def test_multiple_or_nonterminal_completions_are_rejected(self):
        fake_coderabbit(self.bin, helpers.CR_CLEAN + helpers.CR_CLEAN)
        review = self.direct_review()
        self.assertEqual(review['status'], 'incomplete')
        self.assertIn('exactly one', review['note'])
        fake_coderabbit(self.bin, helpers.CR_CLEAN + 'print(json.dumps({"type":"heartbeat"}))')
        review = self.direct_review()
        self.assertEqual(review['status'], 'incomplete')
        self.assertIn('final structured event', review['note'])

    def test_terminal_gate_must_match_exit_status(self):
        fake_coderabbit(self.bin, helpers.CR_CLEAN.replace('"status": "passed"', '"status": "blocked"'))
        review = self.direct_review()
        self.assertEqual(review['status'], 'incomplete')
        self.assertIn('contradicts', review['note'])
        fake_coderabbit(self.bin, helpers.CR_CLEAN + 'sys.exit(2)')
        review = self.direct_review()
        self.assertEqual(review['status'], 'incomplete')
        self.assertIn('contradicts', review['note'])


class TrustedBaseRunnerTests(Harness):
    def test_base_policy_and_base_runner_ignore_pr_edits(self):
        policy = policy_v2([{"name": "unit", "category": "test",
                            "argv": [PY, "-c", "raise SystemExit(1)"]}])
        setup_repo(self.repo, policy)
        # Add reviewed runner to main, and create a feature commit that modifies its code and policy.
        sh(self.repo, 'git', 'switch', 'main')
        target = self.repo/'qa'
        target.mkdir()
        for name in ('aqa.py','aqa_core.py','aqa_policy.py','aqa_report.py','aqa_contracts.py'):
            shutil.copy2(QA/name, target/name)
        commit_all(self.repo, 'install trusted QA runner')
        trusted_base = sh(self.repo,'git','rev-parse','HEAD')
        sh(self.repo, 'git', 'switch', 'feature')
        target.mkdir(exist_ok=True)
        (target/'aqa.py').write_text('raise SystemExit(0)\n')
        (self.repo/'.qa/policy.json').write_text(json.dumps(policy_v2([passing_check()])))
        commit_all(self.repo, 'attempt to bypass QA')
        self.assertEqual(subprocess.run([PY, str(target / 'aqa.py')], check=False, cwd=self.repo).returncode, 0)
        with tempfile.TemporaryDirectory() as root:
            archive_data = subprocess.check_output(['git', 'archive', trusted_base, 'qa'], cwd=self.repo)
            with tarfile.open(fileobj=io.BytesIO(archive_data)) as tar:
                if hasattr(tarfile, 'data_filter'):
                    tar.extractall(root, filter='data')
                else:
                    tar.extractall(root)
            trusted = Path(root) / 'qa' / 'aqa.py'
            proc = subprocess.run([PY, str(trusted), 'ci', '--repo', str(self.repo),
                                   '--base', trusted_base, '--policy-source', 'base'],
                                  check=False, cwd=self.repo, capture_output=True, text=True, env=self.env())
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(self.report()['gate']['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
