import json
import os
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

import helpers  # noqa: F401
from helpers import (CODEX_CLEAN, CR_CLEAN, Harness, fake_codex, fake_coderabbit, hermetic_path, setup_repo)
import aqa_contracts as contracts
import aqa_reviewers as rv


class VerifyToolTests(Harness):
    def verify(self, name):
        with patch.dict(os.environ, {"PATH": hermetic_path(self.tmp, self.bin)}):
            return contracts.verify_tool(name, contracts.load_contracts(), self.tmp)

    def test_ok_when_version_and_flags_match(self):
        fake_codex(self.bin)
        fake_coderabbit(self.bin)
        for name in ("codex", "coderabbit"):
            result = self.verify(name)
            self.assertEqual(result["status"], "ok", result)
        self.assertEqual(self.verify("coderabbit")["version"], "0.9.5")

    def test_missing_tool(self):
        self.assertEqual(self.verify("codex")["status"], "missing")

    def test_version_below_floor_is_violated(self):
        fake_coderabbit(self.bin, version="coderabbit 0.0.1")
        result = self.verify("coderabbit")
        self.assertEqual(result["status"], "violated")
        self.assertIn("older than required", " ".join(result["reasons"]))

    def test_missing_flag_is_violated_and_prefix_flags_do_not_count(self):
        # --base-commit absent but --base present: must NOT satisfy the contract
        fake_coderabbit(self.bin, help_text="--agent\\n--gate\\n--base\\n--include-untracked")
        result = self.verify("coderabbit")
        self.assertEqual(result["status"], "violated")
        self.assertEqual(result["probes"][0]["missing"], ["--base-commit"])

    def test_unparseable_version_depends_on_whether_a_floor_is_enforced(self):
        fake_coderabbit(self.bin, version="dev-build")
        self.assertEqual(self.verify("coderabbit")["status"], "unverifiable")  # floor 0.9.5 enforced
        fake_codex(self.bin, version="dev-build")
        result = self.verify("codex")                                          # no floor for codex yet
        self.assertEqual(result["status"], "ok")
        self.assertIn("not parseable", " ".join(result["reasons"]))


class OutputContractTests(unittest.TestCase):
    def test_coderabbit_stream_contract(self):
        good = [{"type": "heartbeat"}, {"type": "finding", "severity": "minor", "fileName": "a.py", "startLine": 3},
                {"type": "complete", "gate": {"status": "passed", "threshold": "major"}}]
        self.assertEqual(contracts.validate_coderabbit_events(good), [])
        self.assertTrue(contracts.validate_coderabbit_events([{"type": "heartbeat"}]))                      # no complete
        self.assertTrue(contracts.validate_coderabbit_events([{"type": "finding", "severity": "high"}, good[-1]]))
        self.assertTrue(contracts.validate_coderabbit_events([{"type": "finding"}, good[-1]]))              # severity required
        self.assertTrue(contracts.validate_coderabbit_events([{"type": "complete", "gate": {"status": "maybe"}}]))
        self.assertTrue(contracts.validate_coderabbit_events([{"type": "complete"}]))                       # gate required


class ContractDriftTests(unittest.TestCase):
    """The contract must list every flag the orchestrator really passes, so code and contract cannot diverge."""

    def flags(self, argv):
        return {a for a in argv if a.startswith("-") and not a.startswith("---")}

    def test_every_flag_in_the_code_is_in_the_contract(self):
        spec = contracts.load_contracts()["tools"]
        codex_required = set(spec["codex"]["probes"][0]["must_contain"])
        cr_required = set(spec["coderabbit"]["probes"][0]["must_contain"])
        for writable in (False, True):
            used = self.flags(rv.codex_argv("prompt", Path("out"), Path("schema.json"), writable))
            self.assertLessEqual(used, codex_required, "codex flags missing from contract")
        used = self.flags(rv.coderabbit_argv("a" * 40, "major", True))
        self.assertLessEqual(used, cr_required, "coderabbit flags missing from contract")
        self.assertEqual(rv.codex_argv("p", Path("o"))[1], spec["codex"]["probes"][0]["argv"][1])      # 'exec'
        self.assertEqual(rv.coderabbit_argv("a", "major", False)[1], spec["coderabbit"]["probes"][0]["argv"][1])  # 'review'


@unittest.skipUnless(shutil.which("codex"), "codex CLI not installed: real-binary contract NOT exercised here")
class RealCodexContract(unittest.TestCase):
    def test_real_binary_satisfies_contract(self):
        result = contracts.verify_tool("codex", contracts.load_contracts(), Path.cwd())
        self.assertEqual(result["status"], "ok", result["reasons"])


@unittest.skipUnless(shutil.which("coderabbit"), "coderabbit CLI not installed: real-binary contract NOT exercised here")
class RealCodeRabbitContract(unittest.TestCase):
    def test_real_binary_satisfies_contract(self):
        result = contracts.verify_tool("coderabbit", contracts.load_contracts(), Path.cwd())
        self.assertEqual(result["status"], "ok", result["reasons"])


class SmokeCommandTests(Harness):
    def smoke(self, *args):
        out = self.tmp / "smoke-out"
        proc = self.aqa("smoke", "--out", str(out), *args, env=self.env())
        report = json.loads((out / "smoke-report.json").read_text())
        return proc, report

    def test_contract_smoke_without_live_passes_with_good_tools(self):
        fake_codex(self.bin)
        fake_coderabbit(self.bin)
        proc, report = self.smoke()
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("not run", report["tools"]["codex"]["live"])
        self.assertEqual(self.invoked(), [])           # no model call was made

    def test_missing_tool_is_incomplete_and_violation_is_failed(self):
        fake_coderabbit(self.bin)
        proc, report = self.smoke()
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(report["tools"]["codex"]["status"], "missing")
        fake_codex(self.bin, help_text="--ephemeral")
        proc, report = self.smoke()
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(report["tools"]["codex"]["status"], "violated")

    def test_live_smoke_runs_real_invocation_path_and_validates_output(self):
        fake_codex(self.bin)
        fake_coderabbit(self.bin)
        proc, report = self.smoke("--live", "--timeout", "60")
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertEqual(report["tools"]["codex"]["live_status"], "completed")
        self.assertIn("canary_note", report["tools"]["coderabbit"])
        self.assertEqual(len([x for x in self.invoked() if x.startswith(("codex exec", "coderabbit review"))]), 2)

    def test_live_smoke_fails_on_contract_violating_output(self):
        fake_codex(self.bin, behavior='out.write_text(json.dumps({"summary": "x", "findings": [{"severity": "high"}]}))')
        fake_coderabbit(self.bin, behavior='print(json.dumps({"type": "heartbeat"}))')
        proc, report = self.smoke("--live", "--timeout", "60")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(report["tools"]["codex"]["status"], "failed")
        self.assertIn("schema", report["tools"]["codex"]["note"])
        self.assertTrue(report["tools"]["coderabbit"]["contract_violations"])


@unittest.skipUnless(os.getenv("AQA_LIVE_SMOKE") == "1", "set AQA_LIVE_SMOKE=1 (authenticated CLIs; spends tokens) to run the live smoke")
class LiveSmoke(Harness):
    def test_live_smoke_against_real_clis(self):
        proc = self.aqa("smoke", "--live", "--out", str(self.tmp / "live"), env=dict(os.environ))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
