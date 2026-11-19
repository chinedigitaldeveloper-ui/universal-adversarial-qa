"""Human/CI-facing renderings of the evidence report, and pilot metrics over many reports."""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def safe(text: Any, limit: int = 200) -> str:
    """Untrusted text (check names, AI titles) rendered inert for Markdown and log lines."""
    cleaned = "".join(c if c.isprintable() and c not in "`|" else " " for c in str(text))
    return " ".join(cleaned.split())[:limit]


def gh_escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def markdown(report: dict[str, Any]) -> str:
    gate, review = report["gate"], report["review"]
    lines = ["# Adversarial QA Report", "",
             "- Pipeline: `%s` (tool v%s)" % (report["pipeline"], report["tool_version"]),
             "- Repository: `%s`" % safe(report["repo"]),
             "- Base: `%s` (merge-base `%s`), HEAD `%s`" % (safe(report["base"]), report["merge_base"][:12], report["head_sha"][:12]),
             "- Policy: `%s` sha256 `%s` (source: %s)" % (safe(report["policy"]["path"]), report["policy"]["sha256"][:16], report["policy"]["source"]),
             "- Change risk: **%s**: %s" % (report["risk"]["tier"], safe("; ".join(report["risk"]["reasons"][:3]))),
             "- Gate: **%s**" % gate["status"].upper(),
             "- Human review required: **%s**" % ("YES" if review["human_review_required"] else "no"), ""]
    for warning in report.get("warnings", []):
        lines.append("> warning: " + safe(warning, 300))
    if report.get("warnings"):
        lines.append("")
    for part in report["rounds"]:
        lines += ["## Round %d: gate %s" % (part["index"], part["gate"]["status"]), "",
                  "| check | category | required | status | seconds |", "|---|---|---|---|---|"]
        for c in part["checks"]:
            lines.append("| `%s` | %s | %s | %s | %s |" % (safe(c["name"], 60), c["category"], "yes" if c["required"] else "no",
                                                         c["status"], c.get("duration_seconds", "")))
        for name, rv in part["reviews"].items():
            lines.append("")
            lines.append("Reviewer `%s`: %s%s" % (name, rv["status"], (" (%s)" % safe(rv["note"], 240)) if rv.get("note") else ""))
        if part["findings"]:
            lines += ["", "| severity | reviewer | location | title | disposition | verifier |", "|---|---|---|---|---|---|"]
            for f in part["findings"]:
                lines.append("| %s | %s | `%s:%s` | %s | %s | %s |" % (
                    f["severity"], f["reviewer"], safe(f["file"], 80), f["line"] or "?", safe(f["title"], 120),
                    f["disposition"] + (" (recurring)" if f.get("recurring") else ""),
                    (f.get("verification") or {}).get("verdict", "-")))
        if part.get("fix_result"):
            lines += ["", "Fixer: %s, touched %d file(s)" % (part["fix_result"]["status"], len(part["fix_result"]["touched_files"]))]
        lines.append("")
    lines += ["## Gate reasons", ""] + (["- " + safe(r, 300) for r in gate["reasons"]] or ["- none"])
    lines += ["", "## Escalations to a human (advisory)", ""]
    lines += ["- **%s**: %s" % (e["kind"], safe(e["detail"], 300)) for e in review["escalations"]] or ["- none"]
    lines += ["", "## Decision rule", "",
              "Deterministic evidence blocks; AI reviews advise and escalate. A passing report does not authorize a merge:",
              "require branch protection, the `deterministic-qa` check, and human approval.", ""]
    return "\n".join(lines)


def github_outputs(report: dict[str, Any]) -> None:
    """Workflow annotations + step summary. Untrusted strings are escaped (no workflow-command injection)."""
    gate, review = report["gate"], report["review"]
    if os.getenv("GITHUB_ACTIONS") == "true":
        if gate["status"] != "passed":
            print("::error title=AQA gate %s::%s" % (gate["status"], gh_escape(safe("; ".join(gate["reasons"]), 900))))
        for item in review["escalations"][:10]:
            print("::warning title=AQA human review required (%s)::%s" % (item["kind"], gh_escape(safe(item["detail"], 500))))
    target = os.getenv("GITHUB_STEP_SUMMARY")
    if not target:
        return
    last = report["rounds"][-1] if report["rounds"] else {"checks": []}
    rows = ["### Adversarial QA: %s (%s)" % (gate["status"].upper(), report["pipeline"]), "",
            "Change risk **%s**. Human review required: **%s**." % (report["risk"]["tier"], "yes" if review["human_review_required"] else "no"),
            "", "| check | status |", "|---|---|"]
    rows += ["| `%s` | %s |" % (safe(c["name"], 60), c["status"]) for c in last["checks"]]
    if report.get("warnings"):
        rows += ["", "**Warnings:**"] + ["- " + safe(w, 240) for w in report["warnings"][:5]]
    if review["escalations"]:
        rows += ["", "**Escalations (advisory):**"] + ["- %s: %s" % (e["kind"], safe(e["detail"], 200)) for e in review["escalations"][:10]]
    with open(target, "a", encoding="utf-8") as handle:
        handle.write("\n".join(rows) + "\n")


# --------------------------------------------------------------------------- pilot metrics

def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, -(-int(len(ordered) * pct) // 100)) if pct < 100 else len(ordered)
    return round(ordered[min(rank, len(ordered)) - 1], 3)


def collect_reports(paths: list[Path]) -> tuple[list[dict[str, Any]], int]:
    files: list[Path] = []
    for p in paths:
        files += sorted(p.rglob("report.json")) if p.is_dir() else [p]
    reports, invalid = [], 0
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("schema_version") == 2:
                reports.append(data)
                continue
        except (OSError, ValueError):
            pass
        invalid += 1
    return reports, invalid


def pilot_summary(paths: list[Path], expected: dict[str, str], triage: dict[str, str]) -> dict[str, Any]:
    reports, invalid = collect_reports(paths)
    gates = Counter(r["gate"]["status"] for r in reports)
    reasons: Counter[str] = Counter()
    durations = [r["duration_seconds"] for r in reports]
    check_times: dict[str, list[float]] = defaultdict(list)
    reviewer_times: dict[str, list[float]] = defaultdict(list)
    reviewer_status: dict[str, Counter[str]] = defaultdict(Counter)
    tool_status: dict[str, Counter[str]] = defaultdict(Counter)
    escalations: Counter[str] = Counter()
    findings: dict[str, Counter[str]] = defaultdict(Counter)
    labels: dict[str, Counter[str]] = defaultdict(Counter)
    fix_attempts = fix_violations = 0
    for r in reports:
        if r["gate"]["status"] != "passed":
            reasons.update(x[:120] for x in r["gate"]["reasons"])
        for name, status in r.get("tools", {}).items():
            tool_status[name][status["status"]] += 1
        escalations.update(e["kind"] for e in r["review"]["escalations"])
        for part in r["rounds"]:
            for c in part["checks"]:
                if "duration_seconds" in c:
                    check_times[c["name"]].append(c["duration_seconds"])
            for name, rv in part["reviews"].items():
                reviewer_status[name][rv["status"]] += 1
                if rv.get("duration_seconds"):
                    reviewer_times[name].append(rv["duration_seconds"])
            for f in part["findings"]:
                findings[f["reviewer"]][f["severity"]] += 1
                if f["fingerprint"] in triage:
                    labels[f["reviewer"]][triage[f["fingerprint"]]] += 1
            if part.get("fix_result"):
                fix_attempts += 1
                fix_violations += part["fix_result"]["status"] == "violation"
    matrix: Counter[str] = Counter()
    for r in reports:
        for prefix, want in expected.items():
            if r["head_sha"].startswith(prefix):
                matrix["%s->%s" % (want, r["gate"]["status"])] += 1
    graded = sum(matrix.values())
    correct = sum(n for k, n in matrix.items() if k.split("->")[0] == k.split("->")[1])
    precision = {}
    for name, counts in labels.items():
        total = sum(counts.values())
        eligible = counts["actionable"] + counts["wontfix"] + counts["false_positive"]
        confirmed = counts["actionable"] + counts["wontfix"]
        precision[name] = {"labeled": total, "eligible": eligible, "actionable": counts["actionable"],
                           "accepted_risk": counts["wontfix"], "duplicates_excluded": counts["duplicate"],
                           "precision": round(confirmed / eligible, 3) if eligible else None,
                           "false_positive": counts["false_positive"]}
    return {
        "runs": len(reports), "unreadable_reports": invalid, "gate_counts": dict(gates),
        "incomplete_or_failed_reasons": reasons.most_common(10),
        "classification": {"graded": graded, "correct": correct,
                           "accuracy": round(correct / graded, 3) if graded else None, "confusion": dict(matrix)},
        "cli_contracts": {k: dict(v) for k, v in tool_status.items()},
        "review_usefulness": {"findings": {k: dict(v) for k, v in findings.items()}, "triage": precision,
                              "reviewer_completion": {k: dict(v) for k, v in reviewer_status.items()}},
        "latency_seconds": {"run_p50": percentile(durations, 50), "run_p95": percentile(durations, 95),
                            "slowest_checks": sorted(((k, max(v)) for k, v in check_times.items()), key=lambda x: -x[1])[:5],
                            "reviewers": {k: {"p50": percentile(v, 50), "max": max(v)} for k, v in reviewer_times.items()}},
        "cost": "not measured by this tool: wall-clock only; take token/credit spend from provider billing",
        "fix_safety": {"fix_attempts": fix_attempts, "scope_violations": fix_violations},
        "escalations_by_kind": dict(escalations),
    }


def pilot_markdown(s: dict[str, Any]) -> str:
    c = s["classification"]
    lines = ["# Pilot report", "", "Runs: %d (unreadable: %d). Gate counts: %s" % (s["runs"], s["unreadable_reports"], s["gate_counts"]), "",
             "## 1. CLI compatibility", "", "%s" % (s["cli_contracts"] or "no AI runs recorded"), "",
             "## 2. Review usefulness", "", "Findings: %s" % s["review_usefulness"]["findings"],
             "Triage precision: %s" % (s["review_usefulness"]["triage"] or "no labels supplied (--triage)"),
             "Reviewer completion: %s" % s["review_usefulness"]["reviewer_completion"], "",
             "## 3. CI classification", "", "Graded %d, correct %d, accuracy %s; confusion %s" % (
                 c["graded"], c["correct"], c["accuracy"], c["confusion"] or "{}"),
             "Top non-pass reasons: %s" % s["incomplete_or_failed_reasons"], "",
             "## 4. Latency and cost", "", "Run p50/p95: %s / %s s; slowest checks: %s" % (
                 s["latency_seconds"]["run_p50"], s["latency_seconds"]["run_p95"], s["latency_seconds"]["slowest_checks"]),
             "Reviewers: %s" % s["latency_seconds"]["reviewers"], s["cost"], "",
             "## 5. Fix safety", "", "Attempts %d, scope violations %d" % (s["fix_safety"]["fix_attempts"], s["fix_safety"]["scope_violations"]),
             "", "Escalations by kind: %s" % s["escalations_by_kind"], ""]
    return "\n".join(lines)
