"""Tests for v0.4 P0 requirements:
- Explicit finding counts and count invariants
- Canonical working tree provenance (aqa-tree-v1) and mid-run tree mutation handling
- Reviewer degradation semantics and --require-reviewers enforcement
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers
from helpers import (CODEX_CLEAN, CR_CLEAN, CR_FINDING_WHILE_CHANGED, PY, Harness,
                     commit_all, fake_codex, fake_coderabbit, passing_check, policy_v2,
                     setup_repo, sh)
import aqa
import aqa_core as core
import aqa_policy as policy_mod
import aqa_reviewers as reviewers
import aqa_report as report_mod


class TreeProvenanceTests(Harness):
    def test_canonical_encoding_collision_resistance(self):
        # Two repos with trick filenames (e.g., colons, newlines, prefix overlap)
        setup_repo(self.repo)
        fp1 = core.compute_tree_provenance(self.repo, exclude_dir=self.tmp / "out")
        self.assertTrue(fp1["fingerprint"].startswith("aqa-tree-v1:"))

        # Add a file with special chars
        special_file = self.repo / "test:file with spaces and \n newline.txt"
        special_file.write_bytes(b"hello world")
        fp2 = core.compute_tree_provenance(self.repo, exclude_dir=self.tmp / "out")
        self.assertNotEqual(fp1["fingerprint"], fp2["fingerprint"])

        # Change file content only
        special_file.write_bytes(b"hello world modified")
        fp3 = core.compute_tree_provenance(self.repo, exclude_dir=self.tmp / "out")
        self.assertNotEqual(fp2["fingerprint"], fp3["fingerprint"])

    def test_provenance_detects_staged_and_unstaged_changes(self):
        setup_repo(self.repo)
        fp_clean = core.compute_tree_provenance(self.repo)

        # Unstaged change
        (self.repo / "demo.txt").write_text("unstaged modification\n", encoding="utf-8")
        fp_unstaged = core.compute_tree_provenance(self.repo)
        self.assertNotEqual(fp_clean["fingerprint"], fp_unstaged["fingerprint"])

        # Staged change
        sh(self.repo, "git", "add", "demo.txt")
        fp_staged = core.compute_tree_provenance(self.repo)
        self.assertNotEqual(fp_clean["fingerprint"], fp_staged["fingerprint"])

    def test_provenance_detects_untracked_and_deletions(self):
        setup_repo(self.repo)
        fp_clean = core.compute_tree_provenance(self.repo)

        # Untracked non-ignored file
        (self.repo / "new_untracked.bin").write_bytes(b"\x00\xff\xfe\x01\x02\x03")
        fp_untracked = core.compute_tree_provenance(self.repo)
        self.assertNotEqual(fp_clean["fingerprint"], fp_untracked["fingerprint"])
        (self.repo / "new_untracked.bin").unlink()

        # Deletion
        (self.repo / "demo.txt").unlink()
        fp_deleted = core.compute_tree_provenance(self.repo)
        self.assertNotEqual(fp_clean["fingerprint"], fp_deleted["fingerprint"])

    def test_provenance_handles_symlink_without_following_outside_scope(self):
        if os.name != "posix":
            self.skipTest("Symlink POSIX tests")
        setup_repo(self.repo)
        external_target = "/etc/hosts"
        sym = self.repo / "external_link"
        try:
            sym.symlink_to(external_target)
        except OSError:
            self.skipTest("Symlinks not supported in environment")
        fp = core.compute_tree_provenance(self.repo)
        self.assertTrue(fp["fingerprint"].startswith("aqa-tree-v1:"))
        # Symlink target changed
        sym.unlink()
        sym.symlink_to("/etc/passwd")
        fp2 = core.compute_tree_provenance(self.repo)
        self.assertNotEqual(fp["fingerprint"], fp2["fingerprint"])

    def test_provenance_ignores_excluded_directory(self):
        setup_repo(self.repo)
        out_dir = self.repo / ".qa" / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        fp1 = core.compute_tree_provenance(self.repo, exclude_dir=out_dir)

        # Writing to excluded out dir does not mutate tree fingerprint
        (out_dir / "report.json").write_text("{}", encoding="utf-8")
        fp2 = core.compute_tree_provenance(self.repo, exclude_dir=out_dir)
        self.assertEqual(fp1["fingerprint"], fp2["fingerprint"])

    def test_ci_incomplete_when_tree_mutates_under_strict_policy(self):
        # A mutating check under strict provenance policy
        mutating_check = {
            "name": "mutating-check", "category": "test",
            "argv": [PY, "-c", "import pathlib; pathlib.Path('dirty.txt').write_text('mutated')"]
        }
        policy = policy_v2([mutating_check], provenance={"enforce_tree_unchanged": True})
        setup_repo(self.repo, policy)
        res = self.ci()
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        report = self.report()
        self.assertEqual(report["gate"]["status"], "incomplete")
        self.assertTrue(any("provenance" in r.lower() or "working tree modified" in r.lower()
                            for r in report["gate"]["reasons"]))
        self.assertTrue(report.get("provenance", {}).get("tree_changed"))

    def test_ci_passes_with_warning_under_legacy_policy(self):
        mutating_check = {
            "name": "mutating-check", "category": "test",
            "argv": [PY, "-c", "import pathlib; pathlib.Path('dirty.txt').write_text('mutated')"]
        }
        # Default policy without strict provenance
        policy = policy_v2([mutating_check])
        setup_repo(self.repo, policy)
        res = self.ci()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        report = self.report()
        self.assertEqual(report["gate"]["status"], "passed")
        self.assertTrue(any("tree fingerprint changed" in w.lower() or "modified during execution" in w.lower()
                            for w in report.get("warnings", [])))

    def test_review_escalates_on_mid_run_tree_change(self):
        mutating_check = {
            "name": "mutating-check", "category": "test",
            "argv": [PY, "-c", "import pathlib; pathlib.Path('dirty.txt').write_text('mutated')"]
        }
        policy = policy_v2([mutating_check])
        setup_repo(self.repo, policy)
        fake_codex(self.bin)
        fake_coderabbit(self.bin)
        res = self.review("--agents", "both")
        self.assertEqual(res.returncode, 0)
        report = self.report()
        self.assertEqual(report["gate"]["status"], "passed")
        self.assertTrue(report["review"]["human_review_required"])
        self.assertTrue(any(e["kind"] == "tree_mutation_detected" for e in report["review"]["escalations"]))


class FindingCountsTests(Harness):
    def test_explicit_finding_counts_and_invariants(self):
        setup_repo(self.repo)
        # Emit multiple findings from coderabbit with duplicates and questions
        cr_lines = [
            f"print({json.dumps(e)!r})"
            for e in [
                {"type": "finding", "severity": "major", "fileName": "demo.txt", "startLine": 1,
                 "title": "Bug A", "comment": "desc A"},
                {"type": "finding", "severity": "major", "fileName": "demo.txt", "startLine": 1,
                 "title": "Bug A", "comment": "desc A duplicate"},
                {"type": "finding", "severity": "minor", "fileName": "demo.txt", "startLine": 2,
                 "title": "Question: Should this be configurable?", "comment": "question comment"},
            ]
        ]
        behavior = "\n".join(cr_lines) + "\n" + CR_CLEAN
        fake_coderabbit(self.bin, behavior=behavior)
        fake_codex(self.bin)

        # Suppress one finding via resolutions.json
        fp_to_suppress = reviewers.fingerprint("coderabbit", "demo.txt", "Bug A")
        res_file = self.repo / ".qa" / "resolutions.json"
        res_file.write_text(json.dumps({
            "version": 1,
            "resolutions": [{
                "fingerprint": fp_to_suppress,
                "decision": "accepted_risk",
                "accepted_by": "lead",
                "reason": "Known acceptable behavior for this release",
                "expires": "2027-01-01"
            }]
        }), encoding="utf-8")

        res = self.review("--agents", "both")
        self.assertEqual(res.returncode, 0)
        report = self.report()
        round_1 = report["rounds"][0]

        counts = round_1.get("finding_counts")
        self.assertIsNotNone(counts, "round should have finding_counts structure")

        raw_events = counts["raw_cli_events"]
        raw_findings = counts["raw_finding_events"]
        accepted = counts["accepted_findings"]
        deduped = counts["deduplicated_findings"]
        open_f = counts["open_findings"]
        suppressed_f = counts["suppressed_findings"]

        # Invariants:
        # raw_cli_events >= raw_finding_events >= accepted_findings >= deduplicated_findings
        self.assertGreaterEqual(raw_events, raw_findings)
        self.assertGreaterEqual(raw_findings, accepted)
        self.assertGreaterEqual(accepted, deduped)
        # deduplicated_findings == open_findings + suppressed_findings
        self.assertEqual(deduped, open_f + suppressed_f)
        self.assertEqual(suppressed_f, 1)

        # Check by_reviewer
        cr_counts = counts["by_reviewer"]["coderabbit"]
        self.assertEqual(cr_counts["raw_findings"], 3)
        self.assertEqual(cr_counts["accepted"], 3)
        self.assertEqual(cr_counts["deduplicated"], 2)
        self.assertEqual(cr_counts["suppressed"], 1)
        self.assertEqual(cr_counts["open"], 1)

    def test_markdown_summary_clearly_renders_zero_findings(self):
        setup_repo(self.repo)
        fake_codex(self.bin)
        fake_coderabbit(self.bin)
        res = self.review("--agents", "both")
        self.assertEqual(res.returncode, 0)
        md = (self.repo / ".qa" / "out" / "report.md").read_text(encoding="utf-8")
        self.assertIn("0 findings", md.lower())


class ReviewerDegradationTests(Harness):
    def test_degraded_reviewer_escalates_by_default(self):
        setup_repo(self.repo)
        # CodeX review that outputs valid JSON findings but stderr contains rate limit warnings
        codex_stderr_degraded = r'''
out = Path(args[args.index("-o") + 1])
out.write_text(json.dumps({"summary": "review with backoff", "findings": []}))
import sys
sys.stderr.write("warning: rate limit reached, falling back to reduced context window\n")
'''
        fake_codex(self.bin, behavior=codex_stderr_degraded)
        fake_coderabbit(self.bin)
        res = self.review("--agents", "both")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        report = self.report()
        # Default behavior: escalate, NOT incomplete
        self.assertEqual(report["gate"]["status"], "passed")
        self.assertTrue(report["review"]["human_review_required"])
        degraded_esc = [e for e in report["review"]["escalations"] if e["kind"] == "reviewer_degraded"]
        self.assertTrue(len(degraded_esc) > 0, "degraded reviewer must produce reviewer_degraded escalation")
        self.assertEqual(report["rounds"][0]["reviews"]["codex"]["status"], "degraded")

    def test_require_reviewers_fails_with_exit_3_on_degraded_reviewer(self):
        setup_repo(self.repo)
        codex_stderr_degraded = r'''
out = Path(args[args.index("-o") + 1])
out.write_text(json.dumps({"summary": "degraded run", "findings": []}))
import sys
sys.stderr.write("warning: token limit exceeded, partial response returned\n")
'''
        fake_codex(self.bin, behavior=codex_stderr_degraded)
        fake_coderabbit(self.bin)
        res = self.review("--agents", "both", "--require-reviewers")
        # Exit code 3 required when --require-reviewers and reviewer degraded
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        report = self.report()
        self.assertEqual(report["rounds"][0]["reviews"]["codex"]["status"], "degraded")

    def test_require_reviewers_fails_with_exit_3_on_incomplete_or_missing(self):
        setup_repo(self.repo)
        # Missing codex
        fake_coderabbit(self.bin)
        res = self.review("--agents", "both", "--require-reviewers")
        self.assertEqual(res.returncode, 3)

    def test_crashed_verifier_produces_visible_incomplete_evidence_and_escalation(self):
        setup_repo(self.repo)
        fake_coderabbit(self.bin, CR_FINDING_WHILE_CHANGED)
        # Codex verifier crashes with non-zero exit or unhandled error
        crash_verifier = r'''
if "verification" in str(out):
    import sys
    sys.stderr.write("Fatal crash in verifier\n")
    sys.exit(1)
elif "codex-fix" in str(out):
    out.write_text("no-op")
else:
    out.write_text(json.dumps({"summary": "ok", "findings": []}))
'''
        fake_codex(self.bin, behavior=crash_verifier)
        res = self.review("--agents", "both")
        self.assertEqual(res.returncode, 0)
        report = self.report()
        verif = report["rounds"][0]["verification"]
        self.assertEqual(verif["status"], "incomplete")
        # Incomplete verifier escalation
        self.assertTrue(any(e["kind"] == "verifier_incomplete" for e in report["review"]["escalations"]))

    def test_harmless_stderr_does_not_mark_degraded(self):
        setup_repo(self.repo)
        codex_harmless = r'''
out = Path(args[args.index("-o") + 1])
out.write_text(json.dumps({"summary": "ok", "findings": []}))
import sys
sys.stderr.write("[INFO] Configuration loaded from profile\n")
'''
        fake_codex(self.bin, behavior=codex_harmless)
        fake_coderabbit(self.bin)
        res = self.review("--agents", "both")
        self.assertEqual(res.returncode, 0)
        report = self.report()
        self.assertEqual(report["rounds"][0]["reviews"]["codex"]["status"], "completed")
