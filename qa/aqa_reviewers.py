"""Adapters for the AI CLIs (Pipeline A only). Pipeline B never imports this module.

Every adapter: builds argv in a pure function (so contracts can be checked against it), runs the
real tool with a timeout, validates the output against the output contract, and reports
`incomplete` instead of silently treating a malformed run as clean.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from aqa_contracts import validate_against_schema_file, validate_coderabbit_events
from aqa_core import run_process_bounded, SEVERITY, git_raw, run_process, save, save_json, sha256_text

HERE = Path(__file__).resolve().parent
REVIEW_TIMEOUT = 1800
MAX_REVIEW_STREAM_BYTES = 8 * 1024 * 1024
MAX_REVIEW_STDERR_BYTES = 512 * 1024


# --------------------------------------------------------------------------- findings

def finding_id(source: str, file_name: str, line: Any, title: str) -> str:
    return source[:2].upper() + "-" + sha256_text("%s|%s|%s|%s" % (source, file_name, line or "", title.lower().strip()))[:12]


def fingerprint(source: str, file_name: str, title: str) -> str:
    """Line-insensitive identity, used for recurrence detection and human resolutions."""
    normalized = re.sub(r"\s+", " ", title.lower().strip())
    return sha256_text("%s|%s|%s" % (source, file_name, normalized))[:16]


def make_finding(source: str, severity: str, file_name: str, line: Any, title: str, evidence: str,
                 suggested_fix: str = "", suggested_test: str = "", confidence: Any = None) -> dict[str, Any]:
    line = line if isinstance(line, int) and not isinstance(line, bool) else None
    return {"id": finding_id(source, file_name, line, title), "fingerprint": fingerprint(source, file_name, title),
            "reviewer": source, "severity": severity, "file": file_name, "line": line, "title": title,
            "evidence": evidence[:2000], "suggested_fix": suggested_fix[:2000],
            "suggested_test": suggested_test[:1000], "confidence": confidence,
            "disposition": "open", "recurring": False}


def dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for item in findings:
        seen.setdefault(item["id"], item)
    return list(seen.values())


# --------------------------------------------------------------------------- argv builders

def coderabbit_argv(merge_base: str, threshold: str, include_untracked: bool) -> list[str]:
    cmd = ["coderabbit", "review", "--agent", "--gate", threshold, "--base-commit", merge_base]
    if include_untracked:
        cmd.append("--include-untracked")
    return cmd


def codex_argv(prompt: str, out: Path, schema: Path | None = None, writable: bool = False) -> list[str]:
    cmd = ["codex", "exec", "--ephemeral", "--sandbox", "workspace-write" if writable else "read-only",
           "--ignore-user-config", "--ignore-rules"]
    if schema:
        cmd += ["--output-schema", str(schema)]
    return cmd + ["-o", str(out), prompt]


# --------------------------------------------------------------------------- CodeRabbit

def coderabbit_review(repo: Path, merge_base: str, threshold: str, out: Path, files: list[str],
                      timeout: int = REVIEW_TIMEOUT,
                      stream_limit_bytes: int = MAX_REVIEW_STREAM_BYTES) -> dict[str, Any]:
    untracked = bool(git_raw(repo, "ls-files", "--others", "--exclude-standard").strip())
    result = run_process_bounded(coderabbit_argv(merge_base, threshold, untracked), repo, timeout,
                                 stdout_limit=stream_limit_bytes, stderr_limit=MAX_REVIEW_STDERR_BYTES)
    save(out / "coderabbit.ndjson", result["stdout"])
    save(out / "coderabbit.stderr.log", result["stderr"])
    events: list[dict[str, Any]] = []
    non_json = 0
    for line in result["stdout"].splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            non_json += 1
            continue
        if isinstance(event, dict):
            events.append(event)
        else:
            non_json += 1
    violations = validate_coderabbit_events(events)
    if non_json:
        violations.append("stream contains %d non-JSON or non-object line(s)" % non_json)
    if result["truncated"]:
        violations.append("review output exceeded the capture limit or could not be fully drained")
    completions_seen = [i for i, event in enumerate(events) if event.get("type") == "complete"]
    if len(completions_seen) != 1:
        violations.append("expected exactly one terminal complete event; got %d" % len(completions_seen))
    elif completions_seen[0] != len(events) - 1:
        violations.append("complete event is not the final structured event")
    completions = [x for x in events if x.get("type") == "complete"]
    complete = completions[-1] if completions else {}
    skipped = complete.get("status") == "review_skipped"
    gate = complete.get("gate") if isinstance(complete.get("gate"), dict) else {}
    # A blocked gate and a passing process exit cannot both be true; nor can a
    # passing gate plus a CodeRabbit gate-failure exit. Reject contradictory evidence.
    if result["code"] == 0 and gate.get("status") == "blocked":
        violations.append("exit 0 contradicts CodeRabbit gate=blocked")
    if result["code"] == 2 and gate.get("status") == "passed":
        violations.append("exit 2 contradicts CodeRabbit gate=passed")
    failure = (
        result["code"] not in (0, 2) or result["timed_out"] or bool(violations)
        or any(e.get("type") == "error" for e in events) or complete.get("outcome") == "failed"
        or (complete.get("unreviewedFileCount") or 0) > 0 or (skipped and bool(files))
        or bool(complete.get("reused")) or gate.get("threshold", threshold) != threshold
    )
    findings = [make_finding("coderabbit", str(e.get("severity", "info")).lower(), str(e.get("fileName") or ""),
                             e.get("startLine"), str(e.get("title") or e.get("comment") or "CodeRabbit finding")[:300],
                             str(e.get("comment") or ""), str(e.get("codegenInstructions") or ""))
                for e in events if e.get("type") == "finding" and str(e.get("severity", "")).lower() in SEVERITY]
    notes = []
    if result["timed_out"]:
        notes.append("timed out after %ds" % timeout)
    if result["code"] == 127:
        notes.append("coderabbit executable not found")
    notes += violations[:5]
    return {
        "status": "incomplete" if failure else "skipped" if skipped else "completed",
        "exit_code": result["code"], "gate": gate, "findings": findings,
        "completion": {k: complete.get(k) for k in ("status", "outcome", "unreviewedFileCount", "reused", "message")},
        "contract_violations": violations, "non_json_lines": non_json,
        "output_truncated": result["truncated"], "output_limit_exceeded": result["output_limit_exceeded"],
        "duration_seconds": result["duration_seconds"],
        "note": "; ".join(notes) if failure else "",
    }


# --------------------------------------------------------------------------- Codex

def codex_call(repo: Path, prompt: str, schema: Path | None, out: Path, writable: bool = False,
               timeout: int = REVIEW_TIMEOUT) -> dict[str, Any]:
    out.parent.mkdir(parents=True, exist_ok=True)
    result = run_process(codex_argv(prompt, out, schema, writable), repo, timeout)
    save(out.with_suffix(".stderr.log"), result["stderr"])
    base = {"exit_code": result["code"], "duration_seconds": result["duration_seconds"]}
    if result["timed_out"]:
        return {"status": "incomplete", "reason": "Codex timed out after %ds" % timeout, **base}
    if result["code"] != 0 or not out.is_file():
        return {"status": "incomplete", "reason": "Codex missing/failed (exit %s)" % result["code"], **base}
    if not schema:
        return {"status": "completed", "output": str(out), **base}
    try:
        parsed = json.loads(out.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"status": "incomplete", "reason": "Codex output is not valid JSON", **base}
    errors = validate_against_schema_file(parsed, schema)
    if errors:
        return {"status": "incomplete", "reason": "Codex output violates schema: " + "; ".join(errors[:3]), **base}
    return {"status": "completed", "data": parsed, **base}


def codex_review(repo: Path, merge_base: str, out: Path, timeout: int = REVIEW_TIMEOUT) -> dict[str, Any]:
    instructions = (HERE / "prompts" / "redteam.md").read_text(encoding="utf-8")
    prompt = (instructions + "\n\nReview the working tree (tracked and untracked changes) against the fixed base "
              "revision " + merge_base + " (compare with `git diff " + merge_base + "`).\n")
    raw = codex_call(repo, prompt, HERE / "schema" / "codex-review.json", out / "codex-review.json", timeout=timeout)
    if raw["status"] != "completed":
        return {"status": "incomplete", "findings": [], "note": raw["reason"],
                "duration_seconds": raw["duration_seconds"]}
    data = raw["data"]
    findings = [make_finding("codex", f["severity"], str(f["file"]), f["line"], str(f["title"]),
                             str(f["evidence"]), str(f["suggested_fix"]), str(f["suggested_test"]), f["confidence"])
                for f in data["findings"]]
    return {"status": "completed", "findings": findings, "summary": str(data["summary"])[:1000],
            "duration_seconds": raw["duration_seconds"], "note": ""}


def verify_findings(repo: Path, merge_base: str, findings: list[dict[str, Any]], out: Path,
                    timeout: int = REVIEW_TIMEOUT) -> dict[str, Any]:
    """Skeptical read-only pass. Produces triage evidence only; it can never dismiss a finding."""
    if not findings:
        return {"status": "skipped", "assessments": []}
    instructions = (HERE / "prompts" / "verifier.md").read_text(encoding="utf-8")
    payload = json.dumps([{k: f[k] for k in ("id", "reviewer", "severity", "file", "line", "title", "evidence")}
                          for f in findings], ensure_ascii=True)
    prompt = (instructions + "\n\nBase: " + merge_base + "\n\nUntrusted allegations to check:\n" + payload)
    raw = codex_call(repo, prompt, HERE / "schema" / "codex-verification.json", out / "codex-verification.json",
                     timeout=timeout)
    if raw["status"] != "completed":
        return {"status": "incomplete", "assessments": [], "note": raw["reason"]}
    assessments = raw["data"]["assessments"]
    expected = {f["id"] for f in findings}
    assessed = [x["id"] for x in assessments]
    if set(assessed) != expected or len(assessed) != len(expected):
        return {"status": "incomplete", "assessments": assessments,
                "note": "Verifier did not assess every unique finding exactly once"}
    return {"status": "completed", "assessments": assessments}


def remediation(repo: Path, merge_base: str, evidence: dict[str, Any], out: Path,
                fix_policy: dict[str, Any], timeout: int = REVIEW_TIMEOUT) -> dict[str, Any]:
    instructions = (HERE / "prompts" / "fixer.md").read_text(encoding="utf-8")
    bundle = out / "fix-input.json"
    open_findings = [f for f in evidence["findings"] if f["disposition"] == "open"]
    save_json(bundle, {"base": merge_base, "checks": evidence["checks"], "findings": open_findings})
    scope = ("\n\nEdit scope enforced after your run: at most %d files; allowed paths: %s; forbidden paths: %s. "
             "Any edit outside this scope invalidates the run." % (
                 fix_policy["max_files"], ", ".join(fix_policy["allowed_paths"]),
                 ", ".join(fix_policy["forbidden_paths"]) or "(none beyond protected QA/CI files)"))
    prompt = instructions + scope + "\n\nRead the review evidence at: " + str(bundle) + "\nBase: " + merge_base
    return codex_call(repo, prompt, None, out / "codex-fix.md", writable=True, timeout=timeout)
