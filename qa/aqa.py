#!/usr/bin/env python3
"""Portable adversarial QA runner v0.3 (stdlib only, Python 3.10+).

Two independent pipelines:
  ci      Pipeline B. Mandatory, deterministic, no AI, no auto-fix. Exit code is the merge signal.
  review  Pipeline A. Optional local adversarial review: advisory AI findings escalate to a human;
          optional bounded Codex fixes. Never commits, pushes, or merges.

Operating principle: deterministic evidence BLOCKS; AI judgments ADVISE and ESCALATE.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from aqa_contracts import load_contracts, verify_tool  # noqa: E402
from aqa_core import (EXIT_ESCALATED, EXIT_FAILED, EXIT_INCOMPLETE, EXIT_PASSED, SEVERITY, VERSION,  # noqa: E402
                      changed_files, compute_tree_provenance, diff_numstat, emit, file_digests, git, now_iso, resolve_base,
                      run_process, save, save_json, scrubbed_env, git_env, sha256_file)
from aqa_policy import (AGENT_CHOICES, assess_risk, glob_match, is_protected, load_policy,  # noqa: E402
                        load_resolutions, load_triage, policy_diff)
from aqa_report import github_outputs, markdown, pilot_summary, pilot_markdown  # noqa: E402

BASELINE = {"name": "git-diff-whitespace", "category": "format", "required": True}


def compute_finding_counts(reviews: dict[str, Any], raw_findings: list[dict[str, Any]],
                           deduped_findings: list[dict[str, Any]]) -> dict[str, Any]:
    raw_events = sum(r.get("raw_events_count", 1 if r.get("status") in ("completed", "degraded") else 0)
                     for r in reviews.values())
    raw_findings_count = sum(r.get("raw_findings_count", len(r.get("findings", [])))
                             for r in reviews.values())
    accepted = len(raw_findings)
    deduped = len(deduped_findings)
    suppressed = sum(1 for f in deduped_findings if f.get("disposition") == "suppressed")
    open_cnt = sum(1 for f in deduped_findings if f.get("disposition") == "open")

    by_reviewer: dict[str, dict[str, int]] = {}
    for name, r in reviews.items():
        r_raw_events = r.get("raw_events_count", 1 if r.get("status") in ("completed", "degraded") else 0)
        r_raw_findings = r.get("raw_findings_count", len(r.get("findings", [])))
        r_accepted = sum(1 for f in raw_findings if f.get("reviewer") == name)
        r_deduped = sum(1 for f in deduped_findings if f.get("reviewer") == name)
        r_suppressed = sum(1 for f in deduped_findings if f.get("reviewer") == name and f.get("disposition") == "suppressed")
        r_open = sum(1 for f in deduped_findings if f.get("reviewer") == name and f.get("disposition") == "open")
        by_reviewer[name] = {
            "raw_events": r_raw_events,
            "raw_findings": r_raw_findings,
            "accepted": r_accepted,
            "deduplicated": r_deduped,
            "open": r_open,
            "suppressed": r_suppressed,
        }

    from collections import Counter
    open_sev = Counter(f["severity"] for f in deduped_findings if f.get("disposition") == "open")
    supp_sev = Counter(f["severity"] for f in deduped_findings if f.get("disposition") == "suppressed")
    by_severity = {"open": dict(open_sev), "suppressed": dict(supp_sev)}

    return {
        "raw_cli_events": raw_events,
        "raw_finding_events": raw_findings_count,
        "accepted_findings": accepted,
        "deduplicated_findings": deduped,
        "open_findings": open_cnt,
        "suppressed_findings": suppressed,
        "by_reviewer": by_reviewer,
        "by_severity": by_severity,
    }


# =========================================================================== deterministic checks

def classify_exit(code: int, codes: dict[str, Any]) -> str:
    """pass codes -> passed; known fail codes -> failed; any OTHER code from a scanner that declares
    fail codes is a tool error (incomplete), not a verdict. Without declared fail codes, nonzero = failed."""
    if code < 0:  # subprocess was terminated by a POSIX signal (SIGKILL, SIGSEGV, ...).
        return "incomplete"
    if code in codes["pass"]:
        return "passed"
    if code in (126, 127):
        return "incomplete"
    if codes["fail"] is None or code in codes["fail"]:
        return "failed"
    return "incomplete"


def _executable_found(cmd0: str, cwd: Path, env: dict[str, str]) -> bool:
    if "/" in cmd0 or os.sep in cmd0:
        path = Path(cmd0) if Path(cmd0).is_absolute() else cwd / cmd0
        return path.is_file() and os.access(path, os.X_OK)
    return shutil.which(cmd0, path=env.get("PATH")) is not None


def baseline_check(ctx: dict[str, Any], round_dir: Path) -> dict[str, Any]:
    result = run_process(["git", "-c", "core.whitespace=cr-at-eol", "diff", "--check", ctx["merge_base"]],
                         ctx["repo"], 60, env=git_env(), max_output=None)
    log = round_dir / "check-00-git-diff.log"
    save(log, result["stdout"] + "\n" + result["stderr"])
    status = classify_exit(result["code"], {"pass": [0], "fail": [2]})
    return {**BASELINE, "status": status, "exit_code": result["code"], "builtin": True,
            "duration_seconds": result["duration_seconds"], "log": log.name, "log_sha256": sha256_file(log)}


def execute_check(ctx: dict[str, Any], item: dict[str, Any], index: int, round_dir: Path) -> dict[str, Any]:
    repo, policy = ctx["repo"], ctx["policy"]
    cmd = [p.replace("{base}", ctx["merge_base"]).replace("{repo}", str(repo)) for p in item["argv"]]
    cwd = (repo / item["cwd"]) if item["cwd"] else repo
    env = scrubbed_env(policy["env_passthrough"] + item["env_passthrough"], item["env"])
    base = {"name": item["name"], "category": item["category"], "required": item["required"], "argv": cmd}
    if not cwd.is_dir():
        return {**base, "status": "incomplete", "reason": "working directory does not exist: %s" % item["cwd"]}
    if not _executable_found(cmd[0], cwd, env):
        return {**base, "status": "incomplete" if item["required"] else "skipped",
                "reason": "executable '%s' not installed" % cmd[0]}
    result = run_process(cmd, cwd, item["timeout_seconds"], env=env)
    safe = "".join(c if c.isalnum() or c in "_-" else "-" for c in item["name"])
    log = round_dir / ("check-%02d-%s.log" % (index, safe))
    save(log, result["stdout"] + "\n--- stderr ---\n" + result["stderr"])
    status = "incomplete" if result["timed_out"] else classify_exit(result["code"], item["exit_codes"])
    entry = {**base, "status": status, "exit_code": result["code"], "duration_seconds": result["duration_seconds"],
             "log": log.name, "log_sha256": sha256_file(log)}
    if result["timed_out"]:
        entry["reason"] = "timed out after %ds (process group killed)" % item["timeout_seconds"]
    elif status == "incomplete":
        entry["reason"] = ("check process terminated by signal %d" % -result["code"] if result["code"] < 0
                           else "exit code %s is not a declared pass/fail code (tool error, not a verdict)" % result["code"])
    return entry


def skipped_warning(checks: list[dict[str, Any]]) -> list[str]:
    skipped = [c["name"] for c in checks if c["status"] == "skipped"]
    return (["optional checks SKIPPED because the tool is not installed (no evidence from them): " + ", ".join(skipped)]
            if skipped else [])


def run_checks(ctx: dict[str, Any], round_dir: Path, require_checks: bool) -> list[dict[str, Any]]:
    policy = ctx["policy"]
    results = [baseline_check(ctx, round_dir)]
    for index, item in enumerate(policy["checks"], 1):
        emit("  check: %s [%s]" % (item["name"], item["category"]))
        results.append(execute_check(ctx, item, index, round_dir))
    if require_checks:
        if not policy["checks"]:
            results.append({"name": "repo-specific-qa", "category": "other", "required": True, "status": "incomplete",
                            "reason": "No repo-specific checks configured. Configure test/lint/build/security checks."})
        for category in policy["required_categories"]:
            if not any(c["category"] == category and c["required"] for c in policy["checks"]):
                results.append({"name": "coverage:" + category, "category": category, "required": True,
                                "status": "incomplete",
                                "reason": "policy requires category '%s' but no required check covers it" % category})
    return results


# =========================================================================== gate and escalation

def sev_at_least(finding: dict[str, Any], threshold: str) -> bool:
    return SEVERITY.get(finding["severity"], 0) >= SEVERITY[threshold]


def decide_gate(checks: list[dict[str, Any]], reviews: dict[str, Any], findings: list[dict[str, Any]],
                mode: str, threshold: str, agents_selected: bool) -> dict[str, Any]:
    """Blocking evidence only. In advisory mode (default) AI output can never change the status."""
    reasons: list[str] = []
    failed = inconclusive = False
    for check in checks:
        if check["status"] == "failed":
            failed = True
            reasons.append("check failed: " + check["name"])
        elif check["status"] == "incomplete":
            inconclusive = True
            reasons.append("check incomplete: " + check["name"] + (" (%s)" % check["reason"] if check.get("reason") else ""))
    blocking: list[str] = []
    if mode == "blocking" and agents_selected:
        for name, review in reviews.items():
            if review.get("status") == "incomplete":
                inconclusive = True
                reasons.append("review incomplete: " + name)
            if name == "coderabbit" and (review.get("gate") or {}).get("status") == "blocked":
                failed = True
                reasons.append("CodeRabbit native severity gate blocked")
        blocking = [f["id"] for f in findings if f["disposition"] == "open" and sev_at_least(f, threshold)]
        if blocking:
            failed = True
            reasons.append("%d open AI finding(s) at or above %s (policy ai_review.mode=blocking)" % (len(blocking), threshold))
    return {"status": "failed" if failed else "incomplete" if inconclusive else "passed",
            "blocking_findings": blocking, "reasons": reasons}


def build_escalations(ctx: dict[str, Any], reviews: dict[str, Any], findings: list[dict[str, Any]],
                      threshold: str, verification: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Things a HUMAN must look at. None of these change the gate status in advisory mode."""
    esc: list[dict[str, Any]] = []
    for f in findings:
        if f["disposition"] == "open" and sev_at_least(f, threshold):
            verdict = (f.get("verification") or {}).get("verdict", "unverified")
            esc.append({"kind": "finding", "id": f["id"], "severity": f["severity"], "verdict": verdict,
                        "detail": "%s %s: %s (%s:%s)" % (f["reviewer"], f["severity"], f["title"][:160],
                                                         f["file"] or "?", f["line"] or "?")})
    for name, review in reviews.items():
        if review.get("status") == "incomplete":
            esc.append({"kind": "review_gap", "detail": "%s did not complete: %s" % (name, review.get("note", ""))})
        elif review.get("status") == "degraded":
            esc.append({"kind": "reviewer_degraded", "detail": "%s review was degraded: %s" % (name, review.get("note", ""))})
        gate = review.get("gate") or {}
        if name == "coderabbit" and gate.get("status") == "blocked" and not any(
                f["reviewer"] == "coderabbit" for f in findings):  # findings exist (even if a human suppressed them) => no extra signal
            esc.append({"kind": "review_gate_blocked", "detail": "CodeRabbit's native gate blocked without detailed findings"})
    if verification:
        if verification.get("status") == "incomplete":
            esc.append({"kind": "verifier_incomplete", "detail": "Codex verifier did not complete: %s" % verification.get("note", "")})
        elif verification.get("status") == "degraded":
            esc.append({"kind": "verifier_degraded", "detail": "Codex verifier was degraded: %s" % verification.get("note", "")})
    if ctx["protected_changed"]:
        esc.append({"kind": "protected_files_changed", "detail": "QA/CI/ownership files changed: " + ", ".join(ctx["protected_changed"][:8])})
    pd = ctx["policy_diff"]
    if pd.get("weakened"):
        parts = []
        if pd["removed_checks"]:
            parts.append("removed checks: " + ", ".join(pd["removed_checks"]))
        if pd["optional_checks"]:
            parts.append("checks made optional: " + ", ".join(pd["optional_checks"]))
        if pd["removed_required_categories"]:
            parts.append("required categories dropped: " + ", ".join(pd["removed_required_categories"]))
        if pd.get("ai_relaxed"):
            parts.append("AI review relaxed from blocking to advisory")
        esc.append({"kind": "policy_weakened", "detail": "; ".join(parts)})
    if ctx["risk"]["tier"] == "high":
        esc.append({"kind": "high_risk_change", "detail": "; ".join(ctx["risk"]["reasons"][:5])})
    return esc


# =========================================================================== context and reports

def prepare(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo).resolve()
    if git(repo, "rev-parse", "--is-inside-work-tree") != "true":
        raise ValueError("Not a git repository: %s" % repo)
    base_sha, merge_base, warning = resolve_base(repo, args.base)
    policy, meta = load_policy(repo, args.policy, args.policy_source, base_sha)
    out = Path(args.out)
    out = (out if out.is_absolute() else repo / out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    try:
        out.chmod(0o700)
    except OSError:
        pass
    files = changed_files(repo, merge_base, exclude_dir=out)
    counts = diff_numstat(repo, merge_base, files)
    risk = assess_risk(files, counts, policy)
    policy_path = Path(meta["path"])
    if args.policy_source == "base":
        try:
            worktree, _ = load_policy(repo, args.policy, "worktree")
            pdiff = policy_diff(worktree, repo, policy_path, base_sha)
        except ValueError as exc:
            pdiff = {"changed": True, "weakened": False, "removed_checks": [], "optional_checks": [],
                     "removed_required_categories": [], "modified_checks": [], "ai_relaxed": False,
                     "note": "worktree policy unusable: %s" % exc}
    else:
        pdiff = policy_diff(policy, repo, policy_path, base_sha)
    return {"repo": repo, "base": args.base, "base_sha": base_sha, "merge_base": merge_base, "policy": policy,
            "policy_meta": meta, "out": out, "files": files, "risk": risk, "policy_diff": pdiff,
            "protected_changed": [f for f in files if is_protected(f)], "warning": warning,
            "head_sha": git(repo, "rev-parse", "HEAD"),
            "dirty": bool(git(repo, "status", "--porcelain"))}


def new_report(ctx: dict[str, Any], pipeline: str) -> dict[str, Any]:
    return {"schema_version": 2, "pipeline": pipeline, "tool_version": VERSION, "repo": str(ctx["repo"]),
            "base": ctx["base"], "base_sha": ctx["base_sha"], "merge_base": ctx["merge_base"],
            "head_sha": ctx["head_sha"], "dirty_at_start": ctx["dirty"], "started_at": now_iso(),
            "duration_seconds": 0.0,
            "environment": {"python": platform.python_version(), "platform": platform.system(),
                            "ci": os.getenv("CI", "").lower() in ("1", "true", "yes")},
            "policy": ctx["policy_meta"], "policy_changes": ctx["policy_diff"], "risk": ctx["risk"],
            "tools": {}, "rounds": [],
            "gate": {"status": "incomplete", "reasons": ["not finished"], "blocking_findings": []},
            "review": {"selected_agents": "none", "coverage": "none", "human_review_required": False, "escalations": []},
            "warnings": ([ctx["warning"]] if ctx["warning"] else []) + ctx["policy_meta"]["warnings"]}


def persist(ctx: dict[str, Any], report: dict[str, Any], started: float) -> None:
    report["duration_seconds"] = round(time.monotonic() - started, 3)
    save(ctx["out"] / "report.md", markdown(report))
    hashes: dict[str, str] = {}
    if ctx["out"].exists():
        for p in sorted(ctx["out"].rglob("*")):
            if p.is_file() and p.name != "report.json":
                rel = p.relative_to(ctx["out"]).as_posix()
                hashes[rel] = sha256_file(p)
    report["artifact_hashes"] = hashes
    save_json(ctx["out"] / "report.json", report)


def exit_code(report: dict[str, Any], strict_escalation: bool = False) -> int:
    if report.get("require_reviewers_failed"):
        return EXIT_INCOMPLETE
    status = report["gate"]["status"]
    if status == "failed":
        return EXIT_FAILED
    if status != "passed":
        return EXIT_INCOMPLETE
    if strict_escalation and report["review"]["human_review_required"]:
        return EXIT_ESCALATED
    return EXIT_PASSED


def conclude(ctx: dict[str, Any], report: dict[str, Any], started: float, strict: bool = False) -> int:
    persist(ctx, report, started)
    github_outputs(report)
    emit("")
    emit("=== AQA %s pipeline: gate %s ===" % (report["pipeline"], report["gate"]["status"].upper()))
    for reason in report["gate"]["reasons"]:
        emit("  - " + reason)
    if report["review"]["human_review_required"]:
        emit("HUMAN REVIEW REQUIRED (advisory; does not change the gate):")
        for item in report["review"]["escalations"]:
            emit("  - [%s] %s" % (item["kind"], item["detail"]))
    emit("Report: %s" % (ctx["out"] / "report.md"))
    return exit_code(report, strict)


# =========================================================================== Pipeline B: ci

def cmd_ci(args: argparse.Namespace) -> int:
    started = time.monotonic()
    ctx = prepare(args)
    tree_start = compute_tree_provenance(ctx["repo"], exclude_dir=ctx["out"])
    emit("Pipeline B (deterministic PR gate) repo=%s base=%s risk=%s" % (ctx["repo"], ctx["merge_base"][:12], ctx["risk"]["tier"]))
    report = new_report(ctx, "ci")
    round_dir = ctx["out"] / "round-01"
    round_dir.mkdir(parents=True, exist_ok=True)
    checks = run_checks(ctx, round_dir, require_checks=True)
    tree_end = compute_tree_provenance(ctx["repo"], exclude_dir=ctx["out"])
    tree_changed = tree_start["fingerprint"] != tree_end["fingerprint"]
    strict_prov = ctx["policy"].get("provenance", {}).get("enforce_tree_unchanged", False)

    gate = decide_gate(checks, {}, [], "advisory", "major", False)
    if tree_changed:
        if strict_prov:
            gate["status"] = "incomplete"
            gate["reasons"].append("working tree modified during execution (provenance check failed: start=%s end=%s)" % (
                tree_start["fingerprint"][:16], tree_end["fingerprint"][:16]))
        else:
            report["warnings"].append("Working tree modified during execution (tree fingerprint changed: start=%s end=%s)" % (
                tree_start["fingerprint"][:16], tree_end["fingerprint"][:16]))

    esc = build_escalations(ctx, {}, [], "major")
    report["provenance"] = {
        "algorithm": "aqa-tree-v1",
        "tree_fingerprint_start": tree_start["fingerprint"],
        "tree_fingerprint_end": tree_end["fingerprint"],
        "tree_changed": tree_changed,
    }
    report["rounds"].append({"index": 1, "changed_files": ctx["files"], "checks": checks, "reviews": {}, "findings": [],
                             "verification": {"status": "skipped", "assessments": []}, "gate": gate, "escalations": esc})
    report["gate"] = gate
    report["warnings"] += skipped_warning(checks)
    report["review"].update(human_review_required=bool(esc), escalations=esc)
    return conclude(ctx, report, started)


# =========================================================================== Pipeline A: review

def select_agents(requested: str, risk: dict[str, Any]) -> str:
    return risk["agents"] if requested == "auto" else requested


def check_fix_preconditions(args: argparse.Namespace, ctx: dict[str, Any]) -> None:
    if not args.fix:
        return
    if args.agents != "both":
        raise ValueError("--fix requires an explicit --agents both (separation of roles; not allowed with auto)")
    if os.getenv("CI", "").lower() in ("1", "true", "yes"):
        raise ValueError("Automatic fixes are forbidden in CI (Pipeline B never auto-fixes)")
    if not ctx["policy"]["auto_fix"]["enabled"]:
        raise ValueError("Policy does not enable auto_fix. Enable it in the reviewed policy only after the pilot has "
                         "shown acceptable review accuracy.")
    if git(ctx["repo"], "status", "--porcelain"):
        raise ValueError("Fix mode requires a clean working tree; commit/stash changes first")
    if git(ctx["repo"], "branch", "--show-current") in ("main", "master"):
        raise ValueError("Fix mode requires a feature branch, not main/master")


def fix_violations(touched: list[str], fix_policy: dict[str, Any]) -> list[str]:
    problems = []
    for path in touched:
        if is_protected(path):
            problems.append("%s: protected QA/CI/ownership file" % path)
        elif any(glob_match(g, path) for g in fix_policy["forbidden_paths"]):
            problems.append("%s: matches forbidden_paths" % path)
        elif not any(glob_match(g, path) for g in fix_policy["allowed_paths"]):
            problems.append("%s: outside allowed_paths" % path)
    if len(touched) > fix_policy["max_files"]:
        problems.append("fixer touched %d files; auto_fix.max_files is %d" % (len(touched), fix_policy["max_files"]))
    return problems


def cmd_review(args: argparse.Namespace) -> int:
    import aqa_reviewers as rv  # lazy: Pipeline B must never load AI adapters

    started = time.monotonic()
    if not 1 <= args.max_rounds <= 3:
        raise ValueError("--max-rounds must be between 1 and 3")
    ctx = prepare(args)
    policy = ctx["policy"]
    check_fix_preconditions(args, ctx)
    resolutions, res_warnings = load_resolutions(ctx["repo"])
    triage_map, triage_warnings = load_triage(ctx["repo"])
    threshold = policy["ai_review"]["escalate_at"]
    mode = policy["ai_review"]["mode"]
    selected = select_agents(args.agents, ctx["risk"])
    report = new_report(ctx, "review")
    report["warnings"] += res_warnings + triage_warnings
    emit("Pipeline A (local adversarial review) repo=%s base=%s risk=%s agents=%s (requested %s)" % (
        ctx["repo"], ctx["merge_base"][:12], ctx["risk"]["tier"], selected, args.agents))
    if args.agents == "auto":
        emit("  agent selection by risk tier %s: %s" % (ctx["risk"]["tier"], selected))
    contracts = load_contracts()
    tools: dict[str, dict[str, Any]] = {}

    def tool_status(name: str) -> dict[str, Any]:
        if name not in tools:
            tools[name] = verify_tool(name, contracts, ctx["repo"])
            report["tools"] = tools
        return tools[name]

    def contract_gap(name: str) -> dict[str, Any] | None:
        status = tool_status(name)
        if status["status"] == "ok":
            return None
        return {"status": "incomplete", "findings": [], "contract": status["status"], "duration_seconds": 0.0,
                "note": "CLI contract %s: %s" % (status["status"], "; ".join(status["reasons"]))}

    previous: set[str] = set()
    final_gate: dict[str, Any] | None = None
    fix_escalations: list[dict[str, Any]] = []
    final_part: dict[str, Any] = {}
    tree_start = compute_tree_provenance(ctx["repo"], exclude_dir=ctx["out"])
    for index in range(1, args.max_rounds + 1):
        emit("Round %d/%d" % (index, args.max_rounds))
        round_dir = ctx["out"] / ("round-%02d" % index)
        round_dir.mkdir(parents=True, exist_ok=True)
        files = changed_files(ctx["repo"], ctx["merge_base"], exclude_dir=ctx["out"])
        tree_round_start = compute_tree_provenance(ctx["repo"], exclude_dir=ctx["out"])
        checks = run_checks(ctx, round_dir, args.require_checks)
        tree_after_checks = compute_tree_provenance(ctx["repo"], exclude_dir=ctx["out"])
        tree_changed_in_checks = tree_round_start["fingerprint"] != tree_after_checks["fingerprint"]
        reviews: dict[str, Any] = {}
        raw_findings: list[dict[str, Any]] = []
        if selected in ("coderabbit", "both"):
            emit("  reviewer: CodeRabbit")
            reviews["coderabbit"] = contract_gap("coderabbit") or rv.coderabbit_review(
                ctx["repo"], ctx["merge_base"], threshold, round_dir, files)
            raw_findings += reviews["coderabbit"]["findings"]
        if selected in ("codex", "both"):
            emit("  reviewer: Codex independent red-team")
            reviews["codex"] = contract_gap("codex") or rv.codex_review(ctx["repo"], ctx["merge_base"], round_dir)
            raw_findings += reviews["codex"]["findings"]
        findings = rv.dedupe(raw_findings)
        for f in findings:
            f["recurring"] = f["fingerprint"] in previous
            if f["fingerprint"] in resolutions:
                f["disposition"], f["resolution"] = "suppressed", resolutions[f["fingerprint"]]
            if f["fingerprint"] in triage_map:
                f["triage"] = triage_map[f["fingerprint"]]
        verification: dict[str, Any] = {"status": "skipped", "assessments": []}
        open_findings = [f for f in findings if f["disposition"] == "open"]
        if open_findings:
            if tool_status("codex")["status"] == "ok":
                emit("  verifier: Codex read-only (fresh session)")
                verification = rv.verify_findings(ctx["repo"], ctx["merge_base"], open_findings, round_dir)
            else:
                verification = {"status": "unavailable", "assessments": [],
                                "note": "Codex CLI unavailable: " + "; ".join(tool_status("codex")["reasons"])}
        by_id = {a["id"]: a for a in verification.get("assessments", [])}
        for f in findings:
            if f["id"] in by_id and verification["status"] in ("completed", "degraded"):
                f["verification"] = {k: by_id[f["id"]][k] for k in ("verdict", "evidence", "recommended_action")}
        gate = decide_gate(checks, reviews, findings, mode, threshold, selected != "none")
        esc = build_escalations(ctx, reviews, findings, threshold, verification)
        if tree_changed_in_checks:
            esc.append({"kind": "tree_mutation_detected",
                        "detail": "Working tree modified during check execution (start=%s, end=%s)" % (
                            tree_start["fingerprint"][:16], tree_after_checks["fingerprint"][:16])})
        esc += [{"kind": "fix_ineffective", "detail": "finding recurred after a fix attempt: %s" % f["title"][:120]}
                for f in findings if f["recurring"] and f["disposition"] == "open"]

        require_rev_failed = False
        if getattr(args, "require_reviewers", False) and selected != "none":
            for r_name, r_rev in reviews.items():
                if r_rev.get("status") in ("missing", "incomplete", "degraded"):
                    require_rev_failed = True
                    gate["reasons"].append("required reviewer %s is %s: %s" % (
                        r_name, r_rev.get("status"), r_rev.get("note", "")))
        if require_rev_failed:
            report["require_reviewers_failed"] = True

        counts = compute_finding_counts(reviews, raw_findings, findings)
        part = {"index": index, "changed_files": files, "checks": checks, "reviews": reviews, "findings": findings,
                "finding_counts": counts, "verification": verification, "gate": gate, "escalations": esc}
        report["rounds"].append(part)
        final_gate, final_part = gate, part
        report["gate"] = gate
        report["review"] = {"selected_agents": selected, "coverage": "none", "human_review_required": bool(esc),
                            "escalations": esc}
        persist(ctx, report, started)
        emit("  gate: %s (%d findings, %d escalations)" % (gate["status"], len(findings), len(esc)))
        previous |= {f["fingerprint"] for f in open_findings}
        escalated_open = [f for f in open_findings if sev_at_least(f, threshold)]
        if not args.fix or index == args.max_rounds or not (gate["status"] == "failed" or escalated_open):
            break
        if gate["status"] == "incomplete" or any(c["status"] == "incomplete" for c in checks) \
                or any(r["status"] == "incomplete" for r in reviews.values()):
            emit("Stopping fix loop: evidence is incomplete and cannot guide safe repairs.")
            break
        emit("  fixer: Codex workspace-write (explicit opt-in, scope enforced)")
        before = file_digests(ctx["repo"], changed_files(ctx["repo"], ctx["merge_base"], exclude_dir=ctx["out"]))
        outcome = rv.remediation(ctx["repo"], ctx["merge_base"], part, round_dir, policy["auto_fix"])
        after = file_digests(ctx["repo"], changed_files(ctx["repo"], ctx["merge_base"], exclude_dir=ctx["out"]))
        touched = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
        problems = fix_violations(touched, policy["auto_fix"])
        part["fix_result"] = {"status": "violation" if problems else outcome["status"], "touched_files": touched,
                              "violations": problems, "duration_seconds": outcome.get("duration_seconds", 0.0)}
        if problems:
            final_gate = {"status": "incomplete", "blocking_findings": [],
                          "reasons": ["fixer violated its edit scope; inspect and revert manually: " + "; ".join(problems[:5])]}
            fix_escalations = [{"kind": "fix_scope_violation", "detail": "; ".join(problems[:5])}]
            emit("Stopping fix loop: fixer violated edit scope. Nothing was reverted automatically.")
            break
        if outcome["status"] != "completed" or not touched:
            emit("Stopping fix loop: no successful file changes detected.")
            break
    reviews_final = final_part.get("reviews", {})
    coverage = "none" if selected == "none" else (
        "complete" if all(r["status"] in ("completed", "skipped") for r in reviews_final.values()) else "partial")
    report["gate"] = final_gate or report["gate"]
    report["warnings"] += skipped_warning(final_part.get("checks", []))
    all_esc = final_part.get("escalations", []) + fix_escalations
    tree_end = compute_tree_provenance(ctx["repo"], exclude_dir=ctx["out"])
    report["provenance"] = {
        "algorithm": "aqa-tree-v1",
        "tree_fingerprint_start": tree_start["fingerprint"],
        "tree_fingerprint_end": tree_end["fingerprint"],
        "tree_changed": tree_start["fingerprint"] != tree_end["fingerprint"],
    }
    report["review"] = {"selected_agents": selected, "coverage": coverage, "human_review_required": bool(all_esc),
                        "escalations": all_esc,
                        "resolutions_active": len(resolutions)}
    return conclude(ctx, report, started, strict=args.strict_escalation)


# =========================================================================== doctor / contracts / smoke

def cmd_doctor(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    base_sha = git(repo, "rev-parse", "--verify", args.base + "^{commit}") if args.base else None
    policy, meta = load_policy(repo, args.policy, "worktree")
    emit("Repository: %s" % repo)
    emit("Policy: %s (v%s, %d checks, required categories: %s)" % (
        meta["path"], policy["version"], len(policy["checks"]), ", ".join(policy["required_categories"]) or "none"))
    for warning in meta["warnings"]:
        emit("  warning: " + warning)
    if not policy["checks"]:
        emit("  NOT READY: no checks configured; Pipeline B would report INCOMPLETE")
    emit("Git HEAD: %s" % git(repo, "rev-parse", "--short", "HEAD"))
    if base_sha:
        emit("Base: %s" % base_sha)
    contracts = load_contracts()
    bad = False
    for name in contracts["tools"]:
        status = verify_tool(name, contracts, repo)
        emit("Tool %-10s %-12s version=%s %s" % (name, status["status"].upper(), status["version"] or "?",
                                               "; ".join(status["reasons"])))
        bad = bad or status["status"] != "ok"
    emit("Doctor verifies presence, version floor and CLI flags. It does NOT prove authentication, "
         "review quality or test coverage; run `doctor --probe` or `smoke --live` for that.")
    if getattr(args, "probe", False):
        emit("")
        emit("=== Active Capability Probe (--probe) ===")
        emit("NOTE: This operation spends model tokens/credits. A successful probe proves execution")
        emit("capability and authentication, not that the reviewer inspected the entire diff correctly.")
        import aqa_reviewers as rv
        probe_bad = False
        for name in contracts["tools"]:
            emit("Probing %s..." % name)
            tmp = Path(tempfile.mkdtemp(prefix="aqa-probe-"))
            try:
                base = smoke_fixture(tmp)
                round_dir = tmp / "probe-round"
                round_dir.mkdir(parents=True, exist_ok=True)
                if name == "codex":
                    live = rv.codex_review(tmp, base, round_dir, timeout=60)
                else:
                    live = rv.coderabbit_review(tmp, base, "major", round_dir, ["app.py"], timeout=60)
                ok = live["status"] in ("completed", "degraded")
                emit("  %s probe %s (status=%s, latency=%.2fs)" % (
                    name, "PASSED" if ok else "FAILED", live["status"], live.get("duration_seconds", 0.0)))
                if not ok:
                    probe_bad = True
                    emit("    reason: %s" % live.get("note", ""))
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        if probe_bad:
            bad = True
    return EXIT_INCOMPLETE if (args.strict and bad) else EXIT_PASSED


def cmd_contracts_verify(args: argparse.Namespace) -> int:
    contracts = load_contracts()
    names = list(contracts["tools"]) if args.tool == "all" else [args.tool]
    results = [verify_tool(n, contracts, Path.cwd()) for n in names]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            emit("%-11s %-12s version=%-10s min=%s" % (r["tool"], r["status"].upper(), r["version"] or "-", r["min_version"] or "-"))
            for reason in r["reasons"]:
                emit("    " + reason)
    if any(r["status"] == "violated" for r in results):
        return EXIT_FAILED
    return EXIT_PASSED if all(r["status"] == "ok" for r in results) else EXIT_INCOMPLETE


def smoke_fixture(root: Path) -> str:
    """Tiny repo with a seeded canary defect (SQL built by string concatenation)."""
    def sh(*a: str) -> str:
        return subprocess.check_output(a, cwd=root, text=True, stderr=subprocess.STDOUT, env=git_env()).strip()
    sh("git", "init", "-q", "-b", "main")
    sh("git", "config", "user.email", "smoke@example.invalid")
    sh("git", "config", "user.name", "Smoke")
    sh("git", "config", "commit.gpgsign", "false")
    (root / "app.py").write_text('def get_user(db, name):\n    return db.execute("SELECT * FROM users WHERE name = ?", (name,))\n', encoding="utf-8")
    sh("git", "add", ".")
    sh("git", "commit", "-qm", "baseline")
    base = sh("git", "rev-parse", "HEAD")
    sh("git", "switch", "-qc", "feature")
    (root / "app.py").write_text('def get_user(db, name):\n    return db.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n', encoding="utf-8")
    sh("git", "add", ".")
    sh("git", "commit", "-qm", "refactor query")
    return base


def cmd_smoke(args: argparse.Namespace) -> int:
    import aqa_reviewers as rv

    contracts = load_contracts()
    names = list(contracts["tools"]) if args.tool == "all" else [args.tool]
    report: dict[str, Any] = {"schema_version": 1, "tool_version": VERSION, "started_at": now_iso(),
                              "live": args.live, "tools": {}}
    out = Path(args.out).resolve()
    for name in names:
        entry: dict[str, Any] = {"verify": verify_tool(name, contracts, Path.cwd())}
        status = entry["verify"]["status"]
        if status != "ok":
            entry["status"] = status
        elif not args.live:
            entry.update(status="ok", live="not run: pass --live to execute the real tool (needs auth; spends tokens)")
        else:
            tmp = Path(tempfile.mkdtemp(prefix="aqa-smoke-"))
            try:
                base = smoke_fixture(tmp)
                round_dir = out / name
                emit("live smoke: %s on a seeded fixture (timeout %ds)" % (name, args.timeout))
                if name == "codex":
                    live = rv.codex_review(tmp, base, round_dir, timeout=args.timeout)
                else:
                    live = rv.coderabbit_review(tmp, base, "major", round_dir, ["app.py"], timeout=args.timeout)
                ok = live["status"] in ("completed",)
                entry.update(status="ok" if ok else "failed", live_status=live["status"], note=live.get("note", ""),
                             contract_violations=live.get("contract_violations", []),
                             latency_seconds=live.get("duration_seconds"), findings=len(live["findings"]),
                             canary_detected=any(f["file"].endswith("app.py") and SEVERITY[f["severity"]] >= SEVERITY["minor"]
                                                 for f in live["findings"]),
                             canary_note="informational only: LLM recall is not a pass/fail criterion")
            finally:
                if not args.keep_fixture:
                    shutil.rmtree(tmp, ignore_errors=True)
        report["tools"][name] = entry
        emit("%-11s %s" % (name, entry["status"].upper()))
    save_json(out / "smoke-report.json", report)
    emit("Wrote %s" % (out / "smoke-report.json"))
    statuses = {e["status"] for e in report["tools"].values()}
    if statuses & {"violated", "failed"}:
        return EXIT_FAILED
    return EXIT_PASSED if statuses == {"ok"} else EXIT_INCOMPLETE


def cmd_pilot(args: argparse.Namespace) -> int:
    expected = json.loads(Path(args.expected).read_text()) if args.expected else {}
    triage = json.loads(Path(args.triage).read_text()) if args.triage else {}
    summary = pilot_summary([Path(p) for p in args.paths], expected, triage)
    print(json.dumps(summary, indent=2, sort_keys=True) if args.json else pilot_markdown(summary))
    return EXIT_PASSED


def cmd_run_shim(args: argparse.Namespace) -> int:
    print("WARNING: `run` is deprecated in v0.2; use `ci` (Pipeline B) or `review` (Pipeline A).", file=sys.stderr)
    args.strict_escalation = False
    if args.agents == "none":
        if args.fix:
            raise ValueError("--fix requires --agents both (separation of roles)")
        return cmd_ci(args)
    return cmd_review(args)


# =========================================================================== CLI

class Parser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)  # exact flags only: an abbreviation must not mask a typo in a gate
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> None:  # usage errors are configuration errors (3), never 'failed' (2)
        self.print_usage(sys.stderr)
        print("QA configuration error: %s" % message, file=sys.stderr)
        sys.exit(EXIT_INCOMPLETE)


def build_parser() -> Parser:
    parser = Parser(description="Portable adversarial QA runner v%s" % VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser, default_out: str = ".qa/out") -> None:
        p.add_argument("--repo", default=".", help="Git repository path")
        p.add_argument("--base", default="origin/main", help="Base ref or SHA; diffs use its merge-base with HEAD")
        p.add_argument("--policy", default=".qa/policy.json")
        p.add_argument("--policy-source", choices=("worktree", "base"), default="worktree",
                       help="'base' reads the policy from the base revision so a PR cannot weaken its own gate")
        p.add_argument("--out", default=default_out)

    ci = sub.add_parser("ci", help="Pipeline B: deterministic PR gate (no AI, no fixes)")
    common(ci)
    ci.set_defaults(func=cmd_ci)

    review = sub.add_parser("review", help="Pipeline A: optional local adversarial review")
    common(review)
    review.add_argument("--agents", choices=("auto",) + AGENT_CHOICES, default="auto",
                        help="auto selects reviewers by change risk tier (policy risk.agents)")
    review.add_argument("--fix", action="store_true", help="Bounded Codex fix loop; needs policy auto_fix.enabled")
    review.add_argument("--max-rounds", type=int, default=2)
    review.add_argument("--require-checks", action="store_true")
    review.add_argument("--require-reviewers", action="store_true",
                        help="Exit 3 if any selected reviewer is missing, incomplete, or degraded")
    review.add_argument("--strict-escalation", action="store_true", help="Exit 4 when the gate passes but a human must review")
    review.set_defaults(func=cmd_review)

    run = sub.add_parser("run", help="DEPRECATED alias for ci/review")
    common(run)
    run.add_argument("--agents", choices=AGENT_CHOICES, default="both")
    run.add_argument("--fix", action="store_true")
    run.add_argument("--max-rounds", type=int, default=2)
    run.add_argument("--require-checks", action="store_true")
    run.set_defaults(func=cmd_run_shim)

    doctor = sub.add_parser("doctor", help="Check policy, git base and real CLI contracts")
    doctor.add_argument("--repo", default=".")
    doctor.add_argument("--policy", default=".qa/policy.json")
    doctor.add_argument("--base", default=None)
    doctor.add_argument("--strict", action="store_true", help="Exit 3 unless every AI CLI satisfies its contract")
    doctor.add_argument("--probe", action="store_true",
                        help="Execute active capability probe against configured AI CLIs (spends tokens)")
    doctor.set_defaults(func=cmd_doctor)

    contracts = sub.add_parser("contracts", help="CLI contract verification")
    csub = contracts.add_subparsers(dest="contracts_command", required=True)
    verify = csub.add_parser("verify", help="Probe real binaries: version floor + required flags (no auth, no cost)")
    verify.add_argument("--tool", choices=("all", "codex", "coderabbit"), default="all")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=cmd_contracts_verify)

    smoke = sub.add_parser("smoke", help="Real-CLI smoke test; --live runs the tools on a seeded fixture")
    smoke.add_argument("--tool", choices=("all", "codex", "coderabbit"), default="all")
    smoke.add_argument("--live", action="store_true", help="Execute the real tools (authenticated; spends tokens)")
    smoke.add_argument("--timeout", type=int, default=900)
    smoke.add_argument("--out", default=".qa/out/smoke")
    smoke.add_argument("--keep-fixture", action="store_true")
    smoke.set_defaults(func=cmd_smoke)

    pilot = sub.add_parser("pilot-report", help="Aggregate report.json files into pilot metrics")
    pilot.add_argument("paths", nargs="+", help="report.json files or directories to scan")
    pilot.add_argument("--expected", help="JSON {head_sha_prefix: expected gate status} for classification accuracy")
    pilot.add_argument("--triage", help="JSON {finding fingerprint: actionable|false_positive|duplicate|wontfix}")
    pilot.add_argument("--json", action="store_true")
    pilot.set_defaults(func=cmd_pilot)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("QA configuration error: %s" % exc, file=sys.stderr)
        return EXIT_INCOMPLETE
    except Exception:  # an orchestrator bug must never look like a pass or a clean failure
        traceback.print_exc()
        print("QA internal error (treated as INCOMPLETE).", file=sys.stderr)
        return EXIT_INCOMPLETE


if __name__ == "__main__":
    sys.exit(main())
