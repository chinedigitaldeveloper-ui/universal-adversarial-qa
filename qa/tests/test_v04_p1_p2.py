"""Unit and acceptance tests for Universal Adversarial QA v0.4 P1 and P2 features:
- Triage annotations (.qa/triage.json) vs authoritative resolutions (.qa/resolutions.json)
- Question-versus-defect classification (explicit field vs heuristic, non-downgrading invariant)
- Windows compatibility hardening (CLI shims, environment scrubbing, process termination, path normalization)
- Artifact hashes (exact post-redaction bytes) and derived evidence labeling
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers import (
    CR_CLEAN,
    Harness,
    fake_coderabbit,
    fake_codex,
    policy_v2,
    setup_repo,
)

# isort: split
import aqa_reviewers as rv
from aqa_core import (
    EXIT_INCOMPLETE,
    _kill_tree,
    resolve_argv_windows,
    run_process,
    scrubbed_env,
    sha256_file,
    unwrap_cmd_shim,
)
from aqa_policy import is_protected
from aqa_report import markdown, pilot_summary


class HumanTriageTests(Harness):
    def test_triage_annotations_loaded_and_attached_to_findings(self):
        setup_repo(self.repo)
        cr_lines = [
            f"print({json.dumps(e)!r})"
            for e in [
                {"type": "finding", "severity": "minor", "fileName": "demo.txt", "startLine": 1,
                 "title": "Unused import or style issue", "comment": "lint note"},
            ]
        ]
        fake_coderabbit(self.bin, behavior="\n".join(cr_lines) + "\n" + CR_CLEAN)
        fake_codex(self.bin)

        fp = rv.fingerprint("coderabbit", "demo.txt", "Unused import or style issue")
        triage_file = self.repo / ".qa" / "triage.json"
        triage_file.write_text(json.dumps({
            "version": 1,
            "triage": [{
                "fingerprint": fp,
                "status": "investigating",
                "triaged_by": "alice",
                "comment": "Looking into this during sprint cleanup",
                "ticket": "SEC-123"
            }]
        }), encoding="utf-8")

        res = self.review("--agents", "both")
        self.assertEqual(res.returncode, 0)
        report = self.report()
        findings = report["rounds"][0]["findings"]
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIn("triage", f)
        self.assertEqual(f["triage"]["status"], "investigating")
        self.assertEqual(f["triage"]["triaged_by"], "alice")
        self.assertEqual(f["triage"]["ticket"], "SEC-123")
        self.assertEqual(f["disposition"], "open")

    def test_triage_never_suppresses_findings_or_changes_gate(self):
        """Invariant: Triage annotations must NEVER independently change gate results or suppress findings."""
        setup_repo(self.repo, policy_v2(ai_review={"mode": "blocking", "escalate_at": "major"}))
        # Emit a major finding
        cr_lines = [
            f"print({json.dumps(e)!r})"
            for e in [
                {"type": "finding", "severity": "major", "fileName": "demo.txt", "startLine": 1,
                 "title": "Severe Security Flaw", "comment": "injection risk"},
            ]
        ]
        cr_complete_blocked = json.dumps({
            "type": "complete", "status": "review_completed", "outcome": "completed",
            "unreviewedFileCount": 0, "gate": {"status": "blocked", "threshold": "major"}
        })
        fake_coderabbit(self.bin, behavior=f"{chr(10).join(cr_lines)}\nprint({cr_complete_blocked!r})\nsys.exit(2)")
        fake_codex(self.bin)

        fp = rv.fingerprint("coderabbit", "demo.txt", "Severe Security Flaw")
        triage_file = self.repo / ".qa" / "triage.json"
        triage_file.write_text(json.dumps({
            "version": 1,
            "triage": [{
                "fingerprint": fp,
                "status": "wont_fix",
                "triaged_by": "bob",
                "comment": "Developer marked wont_fix in triage, but resolutions.json was not updated"
            }]
        }), encoding="utf-8")

        # In review mode, even though triage says wont_fix, gating disposition MUST remain open and gate must block/escalate
        self.review("--agents", "both")
        report = self.report()
        f = report["rounds"][0]["findings"][0]
        self.assertEqual(f["disposition"], "open", "Triage annotation must never suppress finding")
        self.assertEqual(report["gate"]["status"], "failed")

    def test_triage_file_is_protected(self):
        self.assertTrue(is_protected(".qa/triage.json"))
        self.assertTrue(is_protected(".qa/resolutions.json"))

    def test_malformed_triage_file_fails_closed(self):
        setup_repo(self.repo)
        triage_file = self.repo / ".qa" / "triage.json"
        triage_file.write_text('{"version": 1, "triage": [{"fingerprint": "invalid"}]}', encoding="utf-8")
        res = self.review("--agents", "both")
        self.assertEqual(res.returncode, EXIT_INCOMPLETE)
        self.assertIn("must be 16 lowercase hex characters", res.stderr)

    def test_pilot_summary_with_triage_json(self):
        setup_repo(self.repo)
        report_data = {
            "schema_version": 2, "pipeline": "review", "tool_version": "0.4.0",
            "repo": str(self.repo), "base": "main", "base_sha": "abc", "merge_base": "abc",
            "head_sha": "1234567890", "dirty_at_start": False, "started_at": "2026-01-01T00:00:00Z",
            "duration_seconds": 10.0,
            "policy": {"path": ".qa/policy.json", "sha256": "0"*64, "source": "worktree", "declared_version": 2, "warnings": []},
            "gate": {"status": "passed", "reasons": [], "blocking_findings": []},
            "review": {"selected_agents": "coderabbit", "coverage": "complete", "human_review_required": False, "escalations": []},
            "rounds": [{
                "index": 1, "changed_files": ["demo.txt"], "checks": [], "reviews": {"coderabbit": {"status": "completed", "duration_seconds": 1.0}},
                "findings": [{"reviewer": "coderabbit", "severity": "minor", "fingerprint": "deadbeef12345678", "disposition": "open"}],
                "verification": {}, "gate": {"status": "passed"}, "escalations": []
            }]
        }
        rep_file = self.repo / "test_report.json"
        rep_file.write_text(json.dumps(report_data), encoding="utf-8")

        triage_obj = {
            "version": 1,
            "triage": [{
                "fingerprint": "deadbeef12345678",
                "status": "confirmed",
                "triaged_by": "lead"
            }]
        }
        summary = pilot_summary([rep_file], expected={}, triage=triage_obj)
        cr_triage = summary["review_usefulness"]["triage"].get("coderabbit", {})
        self.assertEqual(cr_triage.get("actionable"), 1)


class QuestionClassificationTests(unittest.TestCase):
    def test_explicit_coderabbit_question_field(self):
        event = {
            "type": "finding", "severity": "minor", "fileName": "app.py", "startLine": 10,
            "title": "Is this intended?", "kind": "question"
        }
        k, src = rv.classify_question("coderabbit", event, "Is this intended?", "details")
        self.assertEqual(k, "question")
        self.assertEqual(src, "explicit")

    def test_heuristic_question_title_prefix(self):
        event = {
            "type": "finding", "severity": "minor", "fileName": "app.py", "startLine": 10,
            "title": "Question: Should we cache this result?", "comment": "perf question"
        }
        k, src = rv.classify_question("coderabbit", event, "Question: Should we cache this result?", "perf question")
        self.assertEqual(k, "question")
        self.assertEqual(src, "heuristic")

    def test_defect_classification_default(self):
        event = {
            "type": "finding", "severity": "major", "fileName": "app.py", "startLine": 10,
            "title": "Buffer overflow in parser", "comment": "out of bounds"
        }
        k, src = rv.classify_question("coderabbit", event, "Buffer overflow in parser", "out of bounds")
        self.assertEqual(k, "defect")
        self.assertEqual(src, "explicit")

    def test_question_never_downgrades_severity_or_changes_escalation(self):
        f = rv.make_finding(
            "coderabbit", "major", "app.py", 10, "Question: Potential memory leak?", "desc",
            kind="question", kind_source="heuristic"
        )
        self.assertEqual(f["severity"], "major")
        self.assertEqual(f["kind"], "question")
        self.assertEqual(f["disposition"], "open")


class WindowsSupportTests(unittest.TestCase):
    def test_resolve_argv_windows_cmd_bat(self):
        with patch("os.name", "nt"), patch.dict("os.environ", {"COMSPEC": "C:\\Windows\\system32\\cmd.exe"}):
            with patch("shutil.which", return_value="C:\\tools\\codex.cmd"):
                resolved = resolve_argv_windows(["codex", "review"])
                self.assertEqual(resolved, 'C:\\Windows\\system32\\cmd.exe /d /s /c "C:\\tools\\codex.cmd review"')

            with patch("shutil.which", return_value="C:\\tools\\coderabbit.bat"):
                resolved = resolve_argv_windows(["coderabbit", "--version"])
                self.assertEqual(resolved, 'C:\\Windows\\system32\\cmd.exe /d /s /c "C:\\tools\\coderabbit.bat --version"')

            with patch("shutil.which", return_value="C:\\Git\\bin\\git.exe"):
                resolved = resolve_argv_windows(["git", "status"])
                self.assertEqual(resolved, ["C:\\Git\\bin\\git.exe", "status"])

    def test_resolve_argv_windows_cmd_with_spaces_and_metacharacters(self):
        with (
            patch("os.name", "nt"),
            patch.dict("os.environ", {"COMSPEC": "C:\\Windows\\system32\\cmd.exe"}),
            patch("shutil.which", return_value="C:\\Program Files (x86)\\tools\\codex.cmd"),
        ):
            cmd = resolve_argv_windows(["codex", "review", "--msg", "Fix: #35 with spaces", "--filter", "a & b | c < d > e ^ f %VAR%"])
            # Must be a string starting with cmd.exe /d /s /c and outer double quotes
            self.assertTrue(isinstance(cmd, str))
            self.assertTrue(cmd.startswith('C:\\Windows\\system32\\cmd.exe /d /s /c "'))
            self.assertTrue(cmd.endswith('"'))
            # Path with spaces must be quoted inside
            self.assertIn('"C:\\Program Files (x86)\\tools\\codex.cmd"', cmd)
            # Argument with spaces must be quoted inside
            self.assertIn('"Fix: #35 with spaces"', cmd)
            # Argument with metacharacters must be quoted inside
            self.assertIn('"a & b | c < d > e ^ f %VAR%"', cmd)

    def test_unwrap_genuine_npm_cmd_shim(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            node_modules_bin = base / "node_modules" / "codex" / "bin"
            node_modules_bin.mkdir(parents=True)
            target_js = node_modules_bin / "codex.js"
            target_js.write_text("console.log('codex js');\n", encoding="utf-8")

            # Standard npm .cmd template generated by npm on Windows
            npm_cmd = base / "codex.cmd"
            npm_cmd.write_text(
                '@ECHO off\r\n'
                'GOTO start\r\n'
                ':find_dp0\r\n'
                'SET dp0=%~dp0\r\n'
                'EXIT /b\r\n'
                ':start\r\n'
                'SETLOCAL\r\n'
                'CALL :find_dp0\r\n'
                'IF EXIST "%dp0%\\node.exe" (\r\n'
                '  SET "_prog=%dp0%\\node.exe"\r\n'
                ') ELSE (\r\n'
                '  SET "_prog=node"\r\n'
                '  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n'
                ')\r\n'
                'endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\node_modules\\codex\\bin\\codex.js" %*\r\n',
                encoding="utf-8"
            )

            unwrapped = unwrap_cmd_shim(str(npm_cmd))
            self.assertIsNotNone(unwrapped)
            self.assertEqual(len(unwrapped), 2)
            self.assertTrue(unwrapped[0].lower().endswith(("node", "node.exe")))
            self.assertEqual(os.path.normcase(os.path.abspath(unwrapped[1])), os.path.normcase(os.path.abspath(str(target_js))))

            with patch("os.name", "nt"):
                resolved = resolve_argv_windows([str(npm_cmd), "exec", "-o", "out.json"])
                self.assertIsInstance(resolved, list)
                self.assertEqual(resolved[:2], unwrapped)
                self.assertEqual(resolved[2:], ["exec", "-o", "out.json"])

    def test_unwrap_sibling_exe_cmd_shim(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tool_exe = base / "codex.exe"
            tool_exe.write_text("mock binary", encoding="utf-8")
            tool_cmd = base / "codex.cmd"
            tool_cmd.write_text('@echo off\r\n"%~dp0\\codex.exe" %*\r\n', encoding="utf-8")

            unwrapped = unwrap_cmd_shim(str(tool_cmd))
            self.assertEqual(unwrapped, [str(tool_exe)])

            with patch("os.name", "nt"):
                resolved = resolve_argv_windows([str(tool_cmd), "--version"])
                self.assertEqual(resolved, [str(tool_exe), "--version"])

    def test_cmd_shim_argument_safety_and_metacharacters(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            out_file = base / "received.json"
            marker_pwned = base / "PWNED.txt"

            target_py = base / "echo_args.py"
            target_py.write_text(
                "import json, sys\n"
                f"with open({str(out_file)!r}, 'w', encoding='utf-8') as f:\n"
                "    json.dump(sys.argv[1:], f)\n",
                encoding="utf-8"
            )

            shim_cmd = base / "tool.cmd"
            shim_cmd.write_text(
                f'@"{sys.executable}" "%~dp0{target_py.name}" %*\r\n',
                encoding="utf-8"
            )

            complex_prompt = (
                "Review findings:\n"
                "Line 1: defect found\n"
                'Line 2: "quoted string" and \'single\'\n'
                "Line 3: env ref %PATH% and %UNDEFINED_VAR%\n"
                f"Line 4: injection attempt & echo PWNED > {marker_pwned!s} | dir < con ^"
            )

            unwrapped = unwrap_cmd_shim(str(shim_cmd))
            self.assertIsNotNone(unwrapped)
            self.assertEqual(unwrapped, [sys.executable, str(target_py)])

            with patch("os.name", "nt"):
                resolved_argv = resolve_argv_windows([str(shim_cmd), "review", complex_prompt])
                self.assertIsInstance(resolved_argv, list)
                self.assertEqual(resolved_argv[0], sys.executable)

            res = run_process(
                resolved_argv if os.name != "nt" else [str(shim_cmd), "review", complex_prompt],
                base,
                seconds=30,
            )
            self.assertEqual(res["code"], 0, res["stderr"])

            self.assertTrue(out_file.is_file(), "Target script did not write output file")
            received_args = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(len(received_args), 2)
            self.assertEqual(received_args[0], "review")
            self.assertEqual(received_args[1], complex_prompt)

            self.assertFalse(marker_pwned.exists(), "Command injection succeeded! marker file was created")
            self.assertIn("%PATH%", received_args[1], "%PATH% was expanded when it should have been literal")
            self.assertIn("\n", received_args[1], "Newlines were truncated")

    def test_degradation_detects_windows_execution_policy_and_sandbox_denials(self):
        samples = [
            "File C:\\tool.ps1 cannot be loaded because running scripts is disabled on this system.",
            "Script execution prevented by execution policy: PSSecurityException UnauthorizedAccess",
            "codex: sandbox error: failed to initialize sandbox: operation not permitted by sandbox",
            "CodeRabbit CLI: execution policy denial when launching helper script",
            "sandbox failure: cannot run in sandbox container",
            "Process launch blocked by security policy"
        ]
        for line in samples:
            reasons = rv.detect_degradation_in_stderr(line)
            self.assertTrue(bool(reasons), f"Failed to detect degradation in: {line}")

    def test_scrubbed_env_windows_case_insensitivity_and_system_vars(self):
        win_env = {
            "SystemRoot": "C:\\Windows",
            "WinDir": "C:\\Windows",
            "ComSpec": "C:\\Windows\\system32\\cmd.exe",
            "Path": "C:\\Windows;C:\\Git\\cmd",
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            "TEMP": "C:\\Temp",
            "TMP": "C:\\Temp",
            "AWS_SECRET_ACCESS_KEY": "supersecret",
            "MY_TOKEN": "secrettoken",
            "ALLOWED_PASSTHROUGH": "safe_val"
        }
        with patch("os.name", "nt"):
            scrubbed = scrubbed_env(passthrough=("ALLOWED_PASSTHROUGH",), source=win_env)
            self.assertIn("SystemRoot", scrubbed)
            self.assertIn("ComSpec", scrubbed)
            self.assertIn("Path", scrubbed)
            self.assertIn("PATHEXT", scrubbed)
            self.assertIn("TEMP", scrubbed)
            self.assertIn("ALLOWED_PASSTHROUGH", scrubbed)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", scrubbed)
            self.assertNotIn("MY_TOKEN", scrubbed)

    def test_kill_tree_windows_invokes_taskkill(self):
        with patch("os.name", "nt"), patch("subprocess.run") as mock_run:
            class DummyProc:
                pid = 9999
                def kill(self): pass
            _kill_tree(DummyProc())
            mock_run.assert_called_once_with(
                ["taskkill", "/F", "/T", "/PID", "9999"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
            )


class EvidenceIntegrityAndP2Tests(Harness):
    def test_artifact_hashes_recorded_post_redaction(self):
        setup_repo(self.repo)
        fake_coderabbit(self.bin)
        fake_codex(self.bin)
        res = self.review("--agents", "both")
        self.assertEqual(res.returncode, 0)
        report = self.report()
        self.assertIn("artifact_hashes", report)
        hashes = report["artifact_hashes"]
        self.assertIn("report.md", hashes)
        # Verify hash matches actual written file on disk
        md_file = self.repo / ".qa" / "out" / "report.md"
        self.assertEqual(hashes["report.md"], sha256_file(md_file))

    def test_derived_evidence_banner_in_markdown(self):
        rep = {
            "pipeline": "ci", "tool_version": "0.4.0", "repo": "/repo", "base": "main",
            "merge_base": "abc123456789", "head_sha": "def123456789",
            "policy": {"path": ".qa/policy.json", "sha256": "0"*64, "source": "worktree"},
            "risk": {"tier": "low", "reasons": []},
            "gate": {"status": "passed", "reasons": []},
            "review": {"selected_agents": "none", "human_review_required": False, "escalations": []},
            "rounds": [],
            "evidence_type": "derived"
        }
        rendered = markdown(rep)
        self.assertIn("Derived Evidence", rendered)
        self.assertIn("analyzed or replayed under v0.4", rendered)
