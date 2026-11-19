"""Unit and acceptance tests for Universal Adversarial QA v0.4 P1 and P2 features:
- Triage annotations (.qa/triage.json) vs authoritative resolutions (.qa/resolutions.json)
- Question-versus-defect classification (explicit field vs heuristic, non-downgrading invariant)
- Windows compatibility hardening (CLI shims, environment scrubbing, process termination, path normalization)
- Artifact hashes (exact post-redaction bytes) and derived evidence labeling
"""
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from aqa_core import (
    EXIT_INCOMPLETE, EXIT_PASSED, compute_tree_provenance,
    resolve_argv_windows, scrubbed_env, _kill_tree, sha256_file
)
from aqa_policy import is_protected, load_triage
import aqa_reviewers as rv
from aqa_report import markdown, pilot_summary
from helpers import (
    CR_CLEAN, Harness, fake_codex, fake_coderabbit, policy_v2, setup_repo
)


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
        fake_coderabbit(self.bin, behavior="\n".join(cr_lines) + "\nprint(%r)\nsys.exit(2)" % cr_complete_blocked)
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
        res = self.review("--agents", "both")
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
                self.assertEqual(resolved, ["C:\\Windows\\system32\\cmd.exe", "/c", "C:\\tools\\codex.cmd", "review"])

            with patch("shutil.which", return_value="C:\\tools\\coderabbit.bat"):
                resolved = resolve_argv_windows(["coderabbit", "--version"])
                self.assertEqual(resolved, ["C:\\Windows\\system32\\cmd.exe", "/c", "C:\\tools\\coderabbit.bat", "--version"])

            with patch("shutil.which", return_value="C:\\Git\\bin\\git.exe"):
                resolved = resolve_argv_windows(["git", "status"])
                self.assertEqual(resolved, ["C:\\Git\\bin\\git.exe", "status"])

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
