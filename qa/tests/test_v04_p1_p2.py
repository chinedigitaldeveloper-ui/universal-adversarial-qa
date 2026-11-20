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
    UnsupportedShimError,
    _kill_tree,
    resolve_argv_windows,
    run_process,
    run_process_bounded,
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
    def test_resolve_argv_windows_cmd_bat_rejects_unsupported_shims(self):
        with patch("os.name", "nt"):
            with patch("shutil.which", return_value="C:\\tools\\codex.cmd"):
                with self.assertRaises(UnsupportedShimError) as ctx:
                    resolve_argv_windows(["codex", "review"])
                self.assertIn("cannot safely execute Windows batch shim", str(ctx.exception))

            with patch("shutil.which", return_value="C:\\tools\\coderabbit.bat"):
                with self.assertRaises(UnsupportedShimError) as ctx:
                    resolve_argv_windows(["coderabbit", "--version"])
                self.assertIn("cannot safely execute Windows batch shim", str(ctx.exception))

            with patch("shutil.which", return_value="C:\\Git\\bin\\git.exe"):
                resolved = resolve_argv_windows(["git", "status"])
                self.assertEqual(resolved, ["C:\\Git\\bin\\git.exe", "status"])

    def test_resolve_argv_windows_cmd_with_spaces_and_metacharacters_fails_closed(self):
        with patch("os.name", "nt"), patch("shutil.which", return_value="C:\\Program Files (x86)\\tools\\codex.cmd"):
            with self.assertRaises(UnsupportedShimError) as ctx:
                resolve_argv_windows(["codex", "review", "--msg", "Fix: #35 with spaces", "--filter", "a & b | c < d > e ^ f %VAR%"])
            self.assertIn("cannot safely execute Windows batch shim", str(ctx.exception))

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

    def test_unwrap_sibling_exe_verifies_invocation_statement_not_mere_existence(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tool_exe = base / "tool.exe"
            tool_exe.write_text("decoy binary", encoding="utf-8")
            actual_exe = base / "actual.exe"
            actual_exe.write_text("actual binary", encoding="utf-8")

            # Case A: Same-stem tool.exe exists, but wrapper explicitly calls actual.exe
            dispatch_cmd = base / "tool.cmd"
            dispatch_cmd.write_text(f'@echo off\r\n"%~dp0\\{actual_exe.name}" --mode=prod %*\r\n', encoding="utf-8")

            unwrapped = unwrap_cmd_shim(str(dispatch_cmd))
            self.assertEqual(unwrapped, [str(actual_exe), "--mode=prod"])

            # Case B: Same-stem tool.exe exists, but wrapper has no invocation statement calling it
            stale_cmd = base / "stale.cmd"
            stale_cmd.write_text("@echo off\r\nREM Sibling tool.exe exists but is not invoked\r\necho No-op\r\n", encoding="utf-8")

            # Must NOT blindly execute tool.exe just because tool.exe exists
            self.assertIsNone(unwrap_cmd_shim(str(stale_cmd)))

            # Case C: Wrapper explicitly calls tool.exe
            explicit_cmd = base / "explicit.cmd"
            explicit_cmd.write_text(f'@echo off\r\n"%~dp0\\{tool_exe.name}" %*\r\n', encoding="utf-8")
            self.assertEqual(unwrap_cmd_shim(str(explicit_cmd)), [str(tool_exe)])

    def test_cmd_shim_misleading_references_in_comments_and_echo_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fake_js = base / "fake.js"
            fake_js.write_text("console.log('fake');\n", encoding="utf-8")
            fake_exe = base / "fake.exe"
            fake_exe.write_text("fake binary", encoding="utf-8")

            mislead_cmd = base / "mislead.cmd"
            mislead_cmd.write_text(
                f"@echo off\r\n"
                f"REM {fake_exe.name} reference in comment\r\n"
                f":: node \"%~dp0\\{fake_js.name}\"\r\n"
                f"echo Running {fake_js.name}...\r\n"
                f"unsupported_dispatch_command %*\r\n",
                encoding="utf-8"
            )

            # Must ignore fake references in comments / echo and fail closed on unsupported_dispatch_command
            self.assertIsNone(unwrap_cmd_shim(str(mislead_cmd)))

    def test_cmd_shim_fixed_arguments_preserved_in_order(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log('cli');\n", encoding="utf-8")

            fixed_cmd = base / "fixed.cmd"
            fixed_cmd.write_text(
                f'@node "%~dp0\\{cli_js.name}" --fixed-flag --mode=strict %*\r\n',
                encoding="utf-8"
            )

            unwrapped = unwrap_cmd_shim(str(fixed_cmd))
            self.assertIsNotNone(unwrapped)
            self.assertTrue(unwrapped[0].lower().endswith(("node", "node.exe")))
            self.assertEqual(os.path.normcase(os.path.abspath(unwrapped[1])), os.path.normcase(os.path.abspath(str(cli_js))))
            self.assertEqual(unwrapped[2:], ["--fixed-flag", "--mode=strict"])

            with patch("os.name", "nt"):
                resolved = resolve_argv_windows([str(fixed_cmd), "user_arg1", "user_arg2"])
                self.assertEqual(resolved[2:], ["--fixed-flag", "--mode=strict", "user_arg1", "user_arg2"])

    def test_cmd_shim_unreproducible_environment_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log('cli');\n", encoding="utf-8")

            env_cmd = base / "env.cmd"
            env_cmd.write_text(
                f'@echo off\r\n'
                f'set CUSTOM_SECRET_KEY=12345\r\n'
                f'set PATH=C:\\custom\\bin;%PATH%\r\n'
                f'node "%~dp0\\{cli_js.name}" %*\r\n',
                encoding="utf-8"
            )

            # Custom environment mutations cannot safely be reproduced without a shell; must fail closed
            self.assertIsNone(unwrap_cmd_shim(str(env_cmd)))

            with patch("os.name", "nt"), self.assertRaises(UnsupportedShimError):
                resolve_argv_windows([str(env_cmd), "--version"])

    def test_cmd_shim_missing_argument_forwarding_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log('cli');\n", encoding="utf-8")

            no_fwd_cmd = base / "no_fwd.cmd"
            no_fwd_cmd.write_text(
                f'@node "%~dp0\\{cli_js.name}"\r\n',
                encoding="utf-8"
            )

            # Missing %* would silently drop reviewer/check arguments; must fail closed
            self.assertIsNone(unwrap_cmd_shim(str(no_fwd_cmd)))

    def test_unsupported_cmd_returns_incomplete_and_never_launches_shell(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            marker_pwned = base / "PWNED.txt"

            unsupported_cmd = base / "unsupported.cmd"
            unsupported_cmd.write_text(
                "@echo off\r\nunsupported_tool_binary %*\r\n",
                encoding="utf-8"
            )

            malicious_prompt = (
                "Review findings:\n"
                "Line 1: defect found\n"
                'Line 2: "quoted string" and \'single\'\n'
                "Line 3: env ref %PATH% and %UNDEFINED_VAR%\n"
                f"Line 4: injection attempt & echo PWNED > {marker_pwned!s} | dir < con ^"
            )

            with patch("os.name", "nt"):
                # 1. Direct resolver check
                with self.assertRaises(UnsupportedShimError):
                    resolve_argv_windows([str(unsupported_cmd), "review", malicious_prompt])

                # 2. run_process returns code 126 with diagnostic error
                res_norm = run_process([str(unsupported_cmd), "review", malicious_prompt], base, seconds=30)
                self.assertEqual(res_norm["code"], 126)
                self.assertIn("cannot safely execute Windows batch shim", res_norm["stderr"])
                self.assertFalse(marker_pwned.exists(), "Command injection executed via run_process!")

                # 3. run_process_bounded returns code 126 with diagnostic error
                res_bounded = run_process_bounded([str(unsupported_cmd), "review", malicious_prompt], base, seconds=30)
                self.assertEqual(res_bounded["code"], 126)
                self.assertIn("cannot safely execute Windows batch shim", res_bounded["stderr"])
                self.assertFalse(marker_pwned.exists(), "Command injection executed via run_process_bounded!")

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

    def test_cmd_shim_rejects_unmodeled_control_flow(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")

            # 1. Exit before command
            shim_exit = base / "exit.cmd"
            shim_exit.write_text(f'@echo off\r\nexit /b 1\r\nnode "%~dp0\\{cli_js.name}" %*\r\n', encoding="utf-8")
            self.assertIsNone(unwrap_cmd_shim(str(shim_exit)))

            # 2. Goto before command
            shim_goto = base / "goto.cmd"
            shim_goto.write_text(f'@echo off\r\ngoto :eof\r\nnode "%~dp0\\{cli_js.name}" %*\r\n', encoding="utf-8")
            self.assertIsNone(unwrap_cmd_shim(str(shim_goto)))

            # 3. Subroutine call before command
            shim_call = base / "call.cmd"
            shim_call.write_text(f'@echo off\r\ncall :sub\r\nnode "%~dp0\\{cli_js.name}" %*\r\n:sub\r\nexit /b 0\r\n', encoding="utf-8")
            self.assertIsNone(unwrap_cmd_shim(str(shim_call)))

            # 4. Tampered npm shim with injected exit directive
            tampered_npm = base / "tampered.cmd"
            tampered_npm.write_text(
                '@ECHO off\r\n'
                'GOTO start\r\n'
                ':find_dp0\r\n'
                'SET dp0=%~dp0\r\n'
                'EXIT /b\r\n'
                ':start\r\n'
                'SETLOCAL\r\n'
                'CALL :find_dp0\r\n'
                'exit /b 1\r\n'
                'IF EXIST "%dp0%\\node.exe" (\r\n'
                '  SET "_prog=%dp0%\\node.exe"\r\n'
                ') ELSE (\r\n'
                '  SET "_prog=node"\r\n'
                '  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n'
                ')\r\n'
                f'endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\{cli_js.name}" %*\r\n',
                encoding="utf-8"
            )
            self.assertIsNone(unwrap_cmd_shim(str(tampered_npm)))

    def test_cmd_shim_fails_closed_when_explicit_interpreter_missing(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")
            cli_py = base / "cli.py"
            cli_py.write_text("print(1)", encoding="utf-8")

            missing_node = base / "pinned_missing_node.exe"
            shim_node = base / "pinned_node.cmd"
            shim_node.write_text(f'@echo off\r\n"{missing_node}" "%~dp0\\{cli_js.name}" %*\r\n', encoding="utf-8")
            # Must fail closed instead of silently falling back to whichever node is on PATH
            self.assertIsNone(unwrap_cmd_shim(str(shim_node)))

            missing_py = base / "pinned_missing_py.exe"
            shim_py = base / "pinned_py.cmd"
            shim_py.write_text(f'@echo off\r\n"{missing_py}" "%~dp0\\{cli_py.name}" %*\r\n', encoding="utf-8")
            # Must fail closed instead of silently falling back to sys.executable
            self.assertIsNone(unwrap_cmd_shim(str(shim_py)))

    def test_cmd_shim_preserves_npm_pathext_resolution_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            dir1 = base / "dir1"
            dir2 = base / "dir2"
            dir1.mkdir()
            dir2.mkdir()

            node_js = dir1 / "node.js"
            node_js.write_text("dummy", encoding="utf-8")
            node_exe = dir2 / "node.exe"
            node_exe.write_text("dummy", encoding="utf-8")

            target_js = base / "tool.js"
            target_js.write_text("console.log(1);", encoding="utf-8")

            npm_cmd = base / "npm_shim.cmd"
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
                f'endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\{target_js.name}" %*\r\n',
                encoding="utf-8"
            )

            test_path = f"{dir1}{os.pathsep}{dir2}"
            with patch.dict(os.environ, {"PATH": test_path, "PATHEXT": ".COM;.EXE;.BAT;.CMD;.JS;.VBS"}):
                unwrapped = unwrap_cmd_shim(str(npm_cmd))
                self.assertIsNotNone(unwrapped)
                # Must select node.exe from dir2 and skip node.js from dir1
                self.assertEqual(os.path.normcase(unwrapped[0]), os.path.normcase(str(node_exe)))

    def test_cmd_shim_rejects_unexpanded_variables_in_fixed_arguments(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")

            # 1. Unexpanded %APPDATA%
            shim_appdata = base / "appdata.cmd"
            shim_appdata.write_text(f'@node "%~dp0\\{cli_js.name}" --config=%APPDATA%\\tool.json %*\r\n', encoding="utf-8")
            self.assertIsNone(unwrap_cmd_shim(str(shim_appdata)))

            # 2. Unexpanded %TEMP%
            shim_temp = base / "temp.cmd"
            shim_temp.write_text(f'@node "%~dp0\\{cli_js.name}" %TEMP%\\cache %*\r\n', encoding="utf-8")
            self.assertIsNone(unwrap_cmd_shim(str(shim_temp)))

            # 3. Unexpanded %USERPROFILE% in direct executable
            tool_exe = base / "tool.exe"
            tool_exe.write_text("binary", encoding="utf-8")
            shim_exe = base / "userprofile.cmd"
            shim_exe.write_text(f'@"{tool_exe}" --profile=%USERPROFILE%\\prof %*\r\n', encoding="utf-8")
            self.assertIsNone(unwrap_cmd_shim(str(shim_exe)))

            # 4. Modeled %~dp0 in fixed flag is expanded safely and accepted
            config_file = base / "config.json"
            config_file.write_text("{}", encoding="utf-8")
            shim_valid = base / "valid_modeled.cmd"
            shim_valid.write_text(f'@node "%~dp0\\{cli_js.name}" --config="%~dp0\\{config_file.name}" %*\r\n', encoding="utf-8")
            unwrapped = unwrap_cmd_shim(str(shim_valid))
            self.assertIsNotNone(unwrapped)
            self.assertEqual(unwrapped[2], f'--config={base}{os.sep}{config_file.name}')

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

    def test_p1_rejects_chained_commands_in_ignored_boilerplate(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")

            # 1. @echo off & exit /b 1 before valid invocation
            shim1 = base / "chained_echo.cmd"
            shim1.write_text(f'@echo off & exit /b 1\r\nnode "%~dp0\\{cli_js.name}" %*\r\n', encoding="utf-8")
            self.assertIsNone(unwrap_cmd_shim(str(shim1)))

            # 2. title & exit /b 1
            shim2 = base / "chained_title.cmd"
            shim2.write_text(f'@title My Tool & exit /b 1\r\nnode "%~dp0\\{cli_js.name}" %*\r\n', encoding="utf-8")
            self.assertIsNone(unwrap_cmd_shim(str(shim2)))

            # 3. rem & exit /b 1
            shim3 = base / "chained_rem.cmd"
            shim3.write_text(f'REM Harmless comment & exit /b 1\r\nnode "%~dp0\\{cli_js.name}" %*\r\n', encoding="utf-8")
            self.assertIsNone(unwrap_cmd_shim(str(shim3)))

    def test_p1_npm_swapped_prog_assignments_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tool_js = base / "tool.js"
            tool_js.write_text("console.log(1);", encoding="utf-8")

            sibling_node = base / "node.exe"
            sibling_node.write_text("binary", encoding="utf-8")

            # Swapped npm template: IF branch sets _prog=node, ELSE branch sets _prog=%dp0%\node.exe
            swapped_cmd = base / "swapped.cmd"
            swapped_cmd.write_text(
                '@ECHO off\r\n'
                'GOTO start\r\n'
                ':find_dp0\r\n'
                'SET dp0=%~dp0\r\n'
                'EXIT /b\r\n'
                ':start\r\n'
                'SETLOCAL\r\n'
                'CALL :find_dp0\r\n'
                'IF EXIST "%dp0%\\node.exe" (\r\n'
                '  SET "_prog=node"\r\n'
                '  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n'
                ') ELSE (\r\n'
                '  SET "_prog=%dp0%\\node.exe"\r\n'
                ')\r\n'
                f'endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\{tool_js.name}" %*\r\n',
                encoding="utf-8"
            )

            # Must fail closed because assignments are not in their exact structural positions
            self.assertIsNone(unwrap_cmd_shim(str(swapped_cmd)))

    def test_p2_inline_quoted_arguments_and_paths_with_spaces(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            folder_with_spaces = base / "my tools"
            folder_with_spaces.mkdir()

            cli_js = folder_with_spaces / "my cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")

            config_json = folder_with_spaces / "a b.json"
            config_json.write_text("{}", encoding="utf-8")

            shim = base / "spaces.cmd"
            shim.write_text(
                '@node "%~dp0\\my tools\\my cli.js" --config="%~dp0\\my tools\\a b.json" --title="My App with Spaces" %*\r\n',
                encoding="utf-8"
            )

            unwrapped = unwrap_cmd_shim(str(shim))
            self.assertIsNotNone(unwrapped)
            self.assertEqual(len(unwrapped), 4)
            self.assertTrue(unwrapped[0].lower().endswith(("node", "node.exe")))
            self.assertEqual(os.path.normcase(unwrapped[1]), os.path.normcase(str(cli_js)))
            self.assertEqual(unwrapped[2], f'--config={folder_with_spaces}{os.sep}a b.json')
            self.assertEqual(unwrapped[3], '--title=My App with Spaces')

    def test_p1_npm_invocation_prefix_anchored_and_strict(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")
            sibling_node = base / "node.exe"
            sibling_node.write_text("binary", encoding="utf-8")

            def make_npm_shim(inv_line: str) -> Path:
                shim = base / f"shim_{abs(hash(inv_line))}.cmd"
                content = (
                    "@ECHO off\r\n"
                    "GOTO start\r\n"
                    ":find_dp0\r\n"
                    "SET dp0=%~dp0\r\n"
                    "EXIT /b\r\n"
                    ":start\r\n"
                    "SETLOCAL\r\n"
                    "CALL :find_dp0\r\n"
                    'IF EXIST "%dp0%\\node.exe" (\r\n'
                    '  SET "_prog=%dp0%\\node.exe"\r\n'
                    ") ELSE (\r\n"
                    '  SET "_prog=node"\r\n'
                    "  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n"
                    ")\r\n"
                    f"{inv_line}\r\n"
                )
                shim.write_text(content, encoding="utf-8")
                return shim

            cli_target = f'"%dp0%\\{cli_js.name}"'
            # 1. Exit before prefix
            s1 = make_npm_shim(f'exit /b 1 & title %COMSPEC% & "%_prog%" {cli_target} %*')
            self.assertIsNone(unwrap_cmd_shim(str(s1)))

            # 2. Unexpected command before prefix
            s2 = make_npm_shim(
                f'echo malicious & title %COMSPEC% & "%_prog%" {cli_target} %*'
            )
            self.assertIsNone(unwrap_cmd_shim(str(s2)))

            # 3. Command before full prefix
            s3 = make_npm_shim(
                "calc.exe & endlocal & goto #_undefined_# 2>NUL || "
                f'title %COMSPEC% & "%_prog%" {cli_target} %*'
            )
            self.assertIsNone(unwrap_cmd_shim(str(s3)))

            # 4. Added command after forwarding expression
            s4 = make_npm_shim(
                "endlocal & goto #_undefined_# 2>NUL || "
                f'title %COMSPEC% & "%_prog%" {cli_target} %* & echo extra'
            )
            self.assertIsNone(unwrap_cmd_shim(str(s4)))

            # 5. Malformed prefix operators: single pipe | instead of ||
            s5 = make_npm_shim(
                "endLocal & goto #_undefined_# 2>NUL | "
                f'title %COMSPEC% & "%_prog%" {cli_target} %*'
            )
            self.assertIsNone(unwrap_cmd_shim(str(s5)))

            # 6. Malformed prefix operators: missing 2>NUL
            s6 = make_npm_shim(
                "endLocal & goto #_undefined_# || "
                f'title %COMSPEC% & "%_prog%" {cli_target} %*'
            )
            self.assertIsNone(unwrap_cmd_shim(str(s6)))

            # 7. Supported: full genuine npm prefix
            s7 = make_npm_shim(
                "endLocal & goto #_undefined_# 2>NUL || "
                f'title %COMSPEC% & "%_prog%" {cli_target} %*'
            )
            unwrapped7 = unwrap_cmd_shim(str(s7))
            self.assertIsNotNone(unwrapped7)
            self.assertEqual(unwrapped7[0], str(sibling_node))
            self.assertEqual(unwrapped7[1], str(cli_js))

            # 8. Supported: standard short title prefix
            s8 = make_npm_shim(f'title %COMSPEC% & "%_prog%" {cli_target} %*')
            unwrapped8 = unwrap_cmd_shim(str(s8))
            self.assertIsNotNone(unwrapped8)
            self.assertEqual(unwrapped8[0], str(sibling_node))
            self.assertEqual(unwrapped8[1], str(cli_js))

    def test_p1_npm_exact_interpreter_assignments(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")
            sibling_node = base / "node.exe"
            sibling_node.write_text("binary", encoding="utf-8")

            def make_custom_npm(if_cond: str, if_body: str, else_body: str) -> Path:
                shim = base / f"custom_{abs(hash((if_cond, if_body, else_body)))}.cmd"
                content = (
                    "@ECHO off\r\n"
                    "GOTO start\r\n"
                    ":find_dp0\r\n"
                    "SET dp0=%~dp0\r\n"
                    "EXIT /b\r\n"
                    ":start\r\n"
                    "SETLOCAL\r\n"
                    "CALL :find_dp0\r\n"
                    f"{if_cond} (\r\n"
                    f"  {if_body}\r\n"
                    ") ELSE (\r\n"
                    f"  {else_body}\r\n"
                    ")\r\n"
                    "endLocal & goto #_undefined_# 2>NUL || "
                    f'title %COMSPEC% & "%_prog%" "%dp0%\\{cli_js.name}" %*\r\n'
                )
                shim.write_text(content, encoding="utf-8")
                return shim

            std_if_cond = 'IF EXIST "%dp0%\\node.exe"'
            std_if_body = 'SET "_prog=%dp0%\\node.exe"'
            std_else_body = 'SET "_prog=node"\r\n  SET PATHEXT=%PATHEXT:;.JS;=;%'

            # 1. Altered executable in IF: evilnode.exe
            s1 = make_custom_npm(
                std_if_cond, 'SET "_prog=%dp0%\\evilnode.exe"', std_else_body
            )
            self.assertIsNone(unwrap_cmd_shim(str(s1)))

            # 2. Extra path components in IF: %dp0%\other\node.exe
            s2 = make_custom_npm(
                std_if_cond, 'SET "_prog=%dp0%\\other\\node.exe"', std_else_body
            )
            self.assertIsNone(unwrap_cmd_shim(str(s2)))

            # 3. Non-exact IF condition: IF EXIST "%dp0%\evilnode.exe"
            s3 = make_custom_npm(
                'IF EXIST "%dp0%\\evilnode.exe"', std_if_body, std_else_body
            )
            self.assertIsNone(unwrap_cmd_shim(str(s3)))

            # 4. Non-exact IF condition: IF EXIST "%dp0%\other\node.exe"
            s4 = make_custom_npm(
                'IF EXIST "%dp0%\\other\\node.exe"', std_if_body, std_else_body
            )
            self.assertIsNone(unwrap_cmd_shim(str(s4)))

            # 5. Extra command in IF branch
            s5 = make_custom_npm(
                std_if_cond,
                'SET "_prog=%dp0%\\node.exe"\r\n  SET "EXTRA=1"',
                std_else_body,
            )
            self.assertIsNone(unwrap_cmd_shim(str(s5)))

            # 6. Altered executable in ELSE branch: _prog=evilnode
            s6 = make_custom_npm(
                std_if_cond,
                std_if_body,
                'SET "_prog=evilnode"\r\n  SET PATHEXT=%PATHEXT:;.JS;=;%',
            )
            self.assertIsNone(unwrap_cmd_shim(str(s6)))

            # 7. Unrecognized variable in ELSE branch
            s7 = make_custom_npm(
                std_if_cond,
                std_if_body,
                'SET "_prog=node"\r\n  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n  SET "EXTRA=1"',
            )
            self.assertIsNone(unwrap_cmd_shim(str(s7)))

            # 8. Modified PATHEXT substitution in ELSE branch
            s8 = make_custom_npm(
                std_if_cond,
                std_if_body,
                'SET "_prog=node"\r\n  SET PATHEXT=%PATHEXT:;.EXE;=;%',
            )
            self.assertIsNone(unwrap_cmd_shim(str(s8)))

    def test_p2_child_environment_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            dir_parent = base / "parent_bin"
            dir_parent.mkdir()
            dir_child = base / "child_bin"
            dir_child.mkdir()

            node_name = "node.exe" if sys.platform == "win32" else "node"
            parent_node = dir_parent / node_name
            parent_node.write_text("parent node", encoding="utf-8")
            child_node = dir_child / node_name
            child_node.write_text("child node", encoding="utf-8")
            if sys.platform != "win32":
                parent_node.chmod(0o755)
                child_node.chmod(0o755)

            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")

            # Wrapper without sibling node.exe that relies on PATH node
            npm_cmd = base / "tool.cmd"
            npm_content = (
                "@ECHO off\r\n"
                "GOTO start\r\n"
                ":find_dp0\r\n"
                "SET dp0=%~dp0\r\n"
                "EXIT /b\r\n"
                ":start\r\n"
                "SETLOCAL\r\n"
                "CALL :find_dp0\r\n"
                'IF EXIST "%dp0%\\node.exe" (\r\n'
                '  SET "_prog=%dp0%\\node.exe"\r\n'
                ") ELSE (\r\n"
                '  SET "_prog=node"\r\n'
                "  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n"
                ")\r\n"
                "endLocal & goto #_undefined_# 2>NUL || "
                f'title %COMSPEC% & "%_prog%" "%dp0%\\{cli_js.name}" %*\r\n'
            )
            npm_cmd.write_text(npm_content, encoding="utf-8")

            # 1. When child env provides PATH, child_node must be selected over parent
            child_env = {"PATH": str(dir_child)}
            with patch.dict(os.environ, {"PATH": str(dir_parent)}):
                unwrapped = unwrap_cmd_shim(str(npm_cmd), env=child_env)
                self.assertIsNotNone(unwrapped)
                self.assertEqual(
                    os.path.normcase(unwrapped[0]), os.path.normcase(str(child_node))
                )

            # 2. Case-insensitive environment keys on Windows (Path instead of PATH)
            case_env = {"Path": str(dir_child)}
            with patch.dict(os.environ, {"PATH": str(dir_parent)}):
                unwrapped = unwrap_cmd_shim(str(npm_cmd), env=case_env)
                self.assertIsNotNone(unwrapped)
                self.assertEqual(
                    os.path.normcase(unwrapped[0]), os.path.normcase(str(child_node))
                )

            # 3. Child env excludes runtime -> fails closed (no parent fallback)
            empty_dir = base / "empty_bin"
            empty_dir.mkdir()
            empty_env = {"PATH": str(empty_dir)}

            py_script = base / "script.py"
            py_script.write_text("print(1)", encoding="utf-8")
            py_cmd = base / "pytool.cmd"
            py_cmd.write_text(
                f'@python "%~dp0\\{py_script.name}" %*\r\n', encoding="utf-8"
            )

            py_name = "python.exe" if sys.platform == "win32" else "python"
            child_py = dir_child / py_name
            child_py.write_text("child py", encoding="utf-8")
            if sys.platform != "win32":
                child_py.chmod(0o755)

            unwrapped_py = unwrap_cmd_shim(str(py_cmd), env=child_env)
            self.assertIsNotNone(unwrapped_py)
            self.assertEqual(
                os.path.normcase(unwrapped_py[0]), os.path.normcase(str(child_py))
            )

            # Child excludes python: must fail closed (sys.executable not used)
            self.assertIsNone(unwrap_cmd_shim(str(py_cmd), env=empty_env))

            # 4. resolve_argv_windows uses child environment
            with (
                patch("os.name", "nt"),
                patch.dict(os.environ, {"PATH": str(dir_parent)}),
            ):
                resolved = resolve_argv_windows(
                    [str(npm_cmd), "--flag"], env=child_env
                )
                self.assertEqual(
                    os.path.normcase(resolved[0]),
                    os.path.normcase(str(child_node)),
                )
                self.assertEqual(resolved[-1], "--flag")

    def test_native_interpreter_targets_enforced(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")

            # 1. Sibling is non-native .cmd: node.cmd must NOT be accepted
            sibling_cmd = base / "node.cmd"
            sibling_cmd.write_text("@echo fake node\r\n", encoding="utf-8")

            npm_cmd = base / "tool.cmd"
            npm_cmd.write_text(
                "@ECHO off\r\n"
                "GOTO start\r\n"
                ":find_dp0\r\n"
                "SET dp0=%~dp0\r\n"
                "EXIT /b\r\n"
                ":start\r\n"
                "SETLOCAL\r\n"
                "CALL :find_dp0\r\n"
                'IF EXIST "%dp0%\\node.exe" (\r\n'
                '  SET "_prog=%dp0%\\node.exe"\r\n'
                ") ELSE (\r\n"
                '  SET "_prog=node"\r\n'
                "  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n"
                ")\r\n"
                "endLocal & goto #_undefined_# 2>NUL || "
                f'title %COMSPEC% & "%_prog%" "%dp0%\\{cli_js.name}" %*\r\n',
                encoding="utf-8",
            )
            bin_dir = base / "bin"
            bin_dir.mkdir()
            fake_node_cmd = bin_dir / "node.cmd"
            fake_node_cmd.write_text("@echo fake\r\n", encoding="utf-8")

            # unwrap_cmd_shim must fail closed because only .cmd shims are in PATH
            self.assertIsNone(
                unwrap_cmd_shim(str(npm_cmd), env={"PATH": str(bin_dir)})
            )

            # 2. Straight-line node wrapper where PATH has node.cmd
            straight_cmd = base / "straight.cmd"
            straight_cmd.write_text(
                f'@node "%~dp0\\{cli_js.name}" %*\r\n', encoding="utf-8"
            )
            self.assertIsNone(
                unwrap_cmd_shim(str(straight_cmd), env={"PATH": str(bin_dir)})
            )

            # 3. Straight-line python wrapper where PATH has python.cmd
            py_script = base / "test.py"
            py_script.write_text("print(1)", encoding="utf-8")
            py_cmd = base / "py.cmd"
            py_cmd.write_text(
                f'@python "%~dp0\\{py_script.name}" %*\r\n', encoding="utf-8"
            )
            fake_py_cmd = bin_dir / "python.cmd"
            fake_py_cmd.write_text("@echo fake\r\n", encoding="utf-8")
            self.assertIsNone(
                unwrap_cmd_shim(str(py_cmd), env={"PATH": str(bin_dir)})
            )

            # 4. Explicit non-native executable target in direct invocation
            direct_cmd = base / "direct.cmd"
            direct_cmd.write_text('@"%~dp0\\node.cmd" %*\r\n', encoding="utf-8")
            self.assertIsNone(unwrap_cmd_shim(str(direct_cmd)))

    def test_p2_npm_quoted_forwarding_rejected(self):
        """Test A: npm template ending with quoted forwarding is rejected."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")

            npm_quoted = base / "npm_quoted.cmd"
            npm_quoted.write_text(
                "@ECHO off\r\n"
                "GOTO start\r\n"
                ":find_dp0\r\n"
                "SET dp0=%~dp0\r\n"
                "EXIT /b\r\n"
                ":start\r\n"
                "SETLOCAL\r\n"
                "CALL :find_dp0\r\n"
                'IF EXIST "%dp0%\\node.exe" (\r\n'
                '  SET "_prog=%dp0%\\node.exe"\r\n'
                ") ELSE (\r\n"
                '  SET "_prog=node"\r\n'
                "  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n"
                ")\r\n"
                "endLocal & goto #_undefined_# 2>NUL || "
                f'title %COMSPEC% & "%_prog%" "%dp0%\\{cli_js.name}" "%*"\r\n',
                encoding="utf-8",
            )
            self.assertIsNone(unwrap_cmd_shim(str(npm_quoted)))

            npm_single = base / "npm_single.cmd"
            npm_single.write_text(
                "@ECHO off\r\n"
                "GOTO start\r\n"
                ":find_dp0\r\n"
                "SET dp0=%~dp0\r\n"
                "EXIT /b\r\n"
                ":start\r\n"
                "SETLOCAL\r\n"
                "CALL :find_dp0\r\n"
                'IF EXIST "%dp0%\\node.exe" (\r\n'
                '  SET "_prog=%dp0%\\node.exe"\r\n'
                ") ELSE (\r\n"
                '  SET "_prog=node"\r\n'
                "  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n"
                ")\r\n"
                "endLocal & goto #_undefined_# 2>NUL || "
                f"title %COMSPEC% & \"%_prog%\" \"%dp0%\\{cli_js.name}\" '%*'\r\n",
                encoding="utf-8",
            )
            self.assertIsNone(unwrap_cmd_shim(str(npm_single)))

    def test_p2_straight_line_quoted_forwarding_rejected(self):
        """Test B: straight-line .cmd wrapper ending with quoted forwarding is rejected."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")

            straight_quoted = base / "straight_quoted.cmd"
            straight_quoted.write_text(
                f'@node "%~dp0\\{cli_js.name}" "%*"\r\n', encoding="utf-8"
            )
            self.assertIsNone(unwrap_cmd_shim(str(straight_quoted)))

            straight_single = base / "straight_single.cmd"
            straight_single.write_text(
                f"@node \"%~dp0\\{cli_js.name}\" '%*'\r\n", encoding="utf-8"
            )
            self.assertIsNone(unwrap_cmd_shim(str(straight_single)))

            direct_exe = base / "tool.exe"
            direct_exe.write_text("dummy", encoding="utf-8")
            direct_quoted = base / "direct_quoted.cmd"
            direct_quoted.write_text(
                f'@"{direct_exe}" "%*"\r\n', encoding="utf-8"
            )
            self.assertIsNone(unwrap_cmd_shim(str(direct_quoted)))

    def test_p2_unquoted_forwarding_preserved(self):
        """Test C: unquoted %* wrappers remain supported and preserve separate arguments."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")

            valid_cmd = base / "tool.cmd"
            valid_cmd.write_text(
                f'@node "%~dp0\\{cli_js.name}" %*\r\n', encoding="utf-8"
            )
            unwrapped = unwrap_cmd_shim(str(valid_cmd))
            self.assertIsNotNone(unwrapped)

            caller_args = ["one", "two", "line 1\nline 2", "with spaces and 'quotes'"]
            with patch("os.name", "nt"):
                resolved = resolve_argv_windows([str(valid_cmd)] + caller_args)
            self.assertEqual(len(resolved), len(unwrapped) + len(caller_args))
            self.assertEqual(resolved[: len(unwrapped)], unwrapped)
            self.assertEqual(resolved[len(unwrapped) :], caller_args)

    def test_p2_quoted_forwarding_fail_closed_propagation(self):
        """Test D: rejected quoted forwarding produces UnsupportedShimError and exit code 126."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cli_js = base / "cli.js"
            cli_js.write_text("console.log(1);", encoding="utf-8")

            quoted_cmd = base / "tool.cmd"
            quoted_cmd.write_text(
                f'@node "%~dp0\\{cli_js.name}" "%*"\r\n', encoding="utf-8"
            )

            with patch("os.name", "nt"):
                with self.assertRaises(UnsupportedShimError) as ctx:
                    resolve_argv_windows([str(quoted_cmd), "one", "two"])
                self.assertIn("cannot safely execute Windows batch shim", str(ctx.exception))
                self.assertIn(str(quoted_cmd), str(ctx.exception))

                with patch("subprocess.Popen") as mock_popen:
                    res = run_process([str(quoted_cmd), "one", "two"], cwd=base)
                    self.assertEqual(res["code"], 126)
                    self.assertIn("cannot safely execute Windows batch shim", res["stderr"])
                    mock_popen.assert_not_called()

                with patch("subprocess.Popen") as mock_popen_bounded:
                    res_bounded = run_process_bounded([str(quoted_cmd), "one", "two"], cwd=base)
                    self.assertEqual(res_bounded["code"], 126)
                    self.assertIn("cannot safely execute Windows batch shim", res_bounded["stderr"])
                    mock_popen_bounded.assert_not_called()


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
