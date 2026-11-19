"""Policy loading/validation (v2, with v1 migration), policy diffing, resolutions and risk tiers."""
from __future__ import annotations

import copy
import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aqa_core import (ENV_NAME, MAX_CHECK_TIMEOUT, SEVERITY, git_env, looks_secret, run_process,
                      sha256_text)

CATEGORIES = ("format", "lint", "types", "test", "build", "sast", "secrets", "deps", "other")
LEVELS = {"low": 0, "medium": 1, "high": 2}
AGENT_CHOICES = ("none", "codex", "coderabbit", "both")
V2_KEYS = {"version", "name", "required_categories", "checks", "env_passthrough", "ai_review", "risk", "auto_fix", "provenance"}
CHECK_KEYS = {"name", "category", "argv", "timeout_seconds", "required", "exit_codes", "env",
              "env_passthrough", "cwd"}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_RESOLUTION_DAYS = 180

DEFAULT_RISK_RULES: list[tuple[str, str, str]] = [
    (".github/workflows/**", "high", "CI workflow definitions"),
    (".qa/**", "high", "QA policy"),
    ("qa/**", "high", "QA runner"),
    ("**/CODEOWNERS", "high", "ownership rules"),
    ("**/auth/**", "high", "authentication code"), ("**/authn/**", "high", "authentication code"),
    ("**/authz/**", "high", "authorization code"), ("**/security/**", "high", "security code"),
    ("**/crypto/**", "high", "cryptography code"), ("**/payment*/**", "high", "payment code"),
    ("**/billing/**", "high", "billing code"), ("**/migrations/**", "high", "database migrations"),
    ("**/migrate/**", "high", "database migrations"),
    ("**/Dockerfile*", "high", "container build"), ("**/docker-compose*.y*ml", "high", "container runtime"),
    ("**/*.tf", "high", "infrastructure as code"), ("**/terraform/**", "high", "infrastructure as code"),
    ("**/k8s/**", "high", "Kubernetes manifests"), ("**/helm/**", "high", "Helm charts"),
    ("**/.env*", "high", "environment files"),
    ("**/package.json", "medium", "dependency manifest"), ("**/package-lock.json", "medium", "lockfile"),
    ("**/pnpm-lock.yaml", "medium", "lockfile"), ("**/yarn.lock", "medium", "lockfile"),
    ("**/requirements*.txt", "medium", "dependency manifest"), ("**/pyproject.toml", "medium", "dependency manifest"),
    ("**/poetry.lock", "medium", "lockfile"), ("**/go.mod", "medium", "dependency manifest"),
    ("**/go.sum", "medium", "lockfile"), ("**/Cargo.toml", "medium", "dependency manifest"),
    ("**/Cargo.lock", "medium", "lockfile"), ("**/pubspec.yaml", "medium", "dependency manifest"),
    ("**/pubspec.lock", "medium", "lockfile"),
    ("**/*.md", "low", "documentation"), ("docs/**", "low", "documentation"),
    ("**/*.png", "low", "image asset"), ("**/*.jpg", "low", "image asset"), ("**/*.svg", "low", "image asset"),
]
PROTECTED_GLOBS = [".qa/policy.json", ".qa/resolutions.json", ".qa/triage.json", ".github/workflows/**", "qa/**",
                   "**/CODEOWNERS"]

_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def glob_regex(pattern: str) -> re.Pattern[str]:
    if pattern not in _GLOB_CACHE:
        out, i = "", 0
        while i < len(pattern):
            c = pattern[i]
            if pattern.startswith("**/", i):
                out += "(?:.*/)?"
                i += 3
                continue
            if pattern.startswith("**", i):
                out += ".*"
                i += 2
                continue
            out += "[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c)
            i += 1
        _GLOB_CACHE[pattern] = re.compile("^" + out + r"\Z", re.S)  # S/\Z: newlines in file names must not dodge rules
    return _GLOB_CACHE[pattern]


def glob_match(pattern: str, path: str) -> bool:
    return bool(glob_regex(pattern).match(path))


def is_protected(path: str) -> bool:
    return any(glob_match(g, path) for g in PROTECTED_GLOBS)


# --------------------------------------------------------------------------- policy

def _fail(message: str) -> None:
    raise ValueError(message)


def _str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        _fail("%s must be an array of non-empty strings" % where)
    return list(value)


def _codes(value: Any, where: str) -> list[int]:
    if (not isinstance(value, list) or not value
            or not all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 255 for x in value)):
        _fail("%s must be a non-empty array of integers 0..255" % where)
    return list(value)


def _check(raw: Any, index: int, repo: Path, strict: bool) -> dict[str, Any]:
    where = "checks[%d]" % index
    if not isinstance(raw, dict):
        _fail(where + " must be an object")
    if strict and set(raw) - CHECK_KEYS:
        _fail("%s has unknown keys: %s" % (where, ", ".join(sorted(set(raw) - CHECK_KEYS))))
    name = raw.get("name")
    if not isinstance(name, str) or not name or (strict and not NAME_RE.match(name)):
        _fail(where + ".name must be a short identifier (letters, digits, . _ -)")
    category = raw.get("category", "other")
    if category not in CATEGORIES:
        _fail("%s.category must be one of: %s" % (where, ", ".join(CATEGORIES)))
    argv = raw.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
        _fail(where + ".argv must be a nonempty array of strings")
    timeout = raw.get("timeout_seconds", 600)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_CHECK_TIMEOUT:
        _fail("%s.timeout_seconds must be an integer in 1..%d" % (where, MAX_CHECK_TIMEOUT))
    required = raw.get("required", True)
    if not isinstance(required, bool):
        _fail(where + ".required must be a boolean")
    codes = raw.get("exit_codes", {})
    if not isinstance(codes, dict) or set(codes) - {"pass", "fail"}:
        _fail(where + ".exit_codes may contain only 'pass' and 'fail'")
    pass_codes = _codes(codes["pass"], where + ".exit_codes.pass") if "pass" in codes else [0]
    fail_codes = _codes(codes["fail"], where + ".exit_codes.fail") if "fail" in codes else None
    if fail_codes is not None and set(pass_codes) & set(fail_codes):
        _fail(where + ".exit_codes pass and fail must not overlap")
    env = raw.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        _fail(where + ".env must map names to string values")
    for key in env:
        if not ENV_NAME.match(key) or looks_secret(key):
            _fail("%s.env name '%s' is invalid or secret-like; never put secrets in policy" % (where, key))
    passthrough = _str_list(raw.get("env_passthrough", []), where + ".env_passthrough")
    if not all(ENV_NAME.match(x) for x in passthrough):
        _fail(where + ".env_passthrough contains an invalid variable name")
    cwd = raw.get("cwd")
    if cwd is not None:
        if not isinstance(cwd, str) or not cwd:
            _fail(where + ".cwd must be a relative directory string")
        resolved = (repo / cwd).resolve()
        if resolved != repo.resolve() and repo.resolve() not in resolved.parents:
            _fail(where + ".cwd must stay inside the repository")
    return {"name": name, "category": category, "argv": list(argv), "timeout_seconds": timeout,
            "required": required, "exit_codes": {"pass": pass_codes, "fail": fail_codes},
            "env": dict(env), "env_passthrough": passthrough, "cwd": cwd}


def normalize_policy(data: Any, repo: Path) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(data, dict):
        _fail("Policy must be a JSON object")
    version = data.get("version")
    warnings: list[str] = []
    if version == 1:
        block_at = data.get("block_at", "major")
        if block_at not in SEVERITY or block_at == "none":
            _fail("block_at must be critical, major, minor, trivial, or info")
        raw: dict[str, Any] = {"name": data.get("name", "unnamed"), "checks": data.get("checks", []),
                               "required_categories": [],
                               "ai_review": {"mode": "blocking", "escalate_at": block_at}}
        warnings.append("Policy version 1 is deprecated: AI findings stay BLOCKING and no required coverage "
                        "categories apply. Migrate to version 2 (see CHANGELOG.md).")
        strict = False
    elif version == 2:
        unknown = set(data) - V2_KEYS
        if unknown:
            _fail("Unknown policy keys: %s" % ", ".join(sorted(unknown)))
        raw, strict = data, True
    else:
        _fail("Policy must declare \"version\": 2 (version 1 is accepted with a deprecation warning)")
    checks_raw = raw.get("checks", [])
    if not isinstance(checks_raw, list):
        _fail("checks must be a list")
    checks = [_check(item, i, repo, strict) for i, item in enumerate(checks_raw)]
    names = [c["name"] for c in checks]
    if len(set(names)) != len(names):
        _fail("check names must be unique")
    required = raw.get("required_categories", ["test"])
    if not isinstance(required, list) or any(x not in CATEGORIES for x in required):
        _fail("required_categories must be a list of: %s" % ", ".join(CATEGORIES))
    ai = raw.get("ai_review", {})
    if not isinstance(ai, dict) or set(ai) - {"mode", "escalate_at"}:
        _fail("ai_review may contain only 'mode' and 'escalate_at'")
    mode = ai.get("mode", "advisory")
    escalate = ai.get("escalate_at", "major")
    if mode not in ("advisory", "blocking"):
        _fail("ai_review.mode must be 'advisory' or 'blocking'")
    if escalate not in SEVERITY or escalate == "none":
        _fail("ai_review.escalate_at must be critical, major, minor, trivial, or info")
    risk = raw.get("risk", {})
    if not isinstance(risk, dict) or set(risk) - {"rules", "agents", "medium_lines", "high_lines", "high_files"}:
        _fail("risk may contain only rules, agents, medium_lines, high_lines, high_files")
    rules = risk.get("rules", [])
    if not isinstance(rules, list):
        _fail("risk.rules must be a list")
    for i, rule in enumerate(rules):
        if (not isinstance(rule, dict) or not isinstance(rule.get("glob"), str)
                or rule.get("level") not in LEVELS):
            _fail("risk.rules[%d] needs a glob and level low|medium|high" % i)
    agents = {"low": "none", "medium": "coderabbit", "high": "both"}
    agents.update(risk.get("agents", {}))
    if set(agents) - set(LEVELS) or any(v not in AGENT_CHOICES for v in agents.values()):
        _fail("risk.agents maps low|medium|high to none|codex|coderabbit|both")
    limits = {k: risk.get(k, d) for k, d in (("medium_lines", 40), ("high_lines", 500), ("high_files", 20))}
    if any(not isinstance(v, int) or isinstance(v, bool) or v < 1 for v in limits.values()):
        _fail("risk.medium_lines / high_lines / high_files must be positive integers")
    fix = raw.get("auto_fix", {})
    if not isinstance(fix, dict) or set(fix) - {"enabled", "max_files", "allowed_paths", "forbidden_paths"}:
        _fail("auto_fix may contain only enabled, max_files, allowed_paths, forbidden_paths")
    max_files = fix.get("max_files", 10)
    if not isinstance(max_files, int) or isinstance(max_files, bool) or not 1 <= max_files <= 100:
        _fail("auto_fix.max_files must be an integer in 1..100")
    if not isinstance(fix.get("enabled", False), bool):
        _fail("auto_fix.enabled must be a boolean")
    prov = raw.get("provenance", {})
    if not isinstance(prov, dict) or set(prov) - {"enforce_tree_unchanged", "enforce_clean_tree"}:
        _fail("provenance may contain only 'enforce_tree_unchanged' and 'enforce_clean_tree'")
    policy = {
        "version": version, "name": raw.get("name", "unnamed"), "checks": checks,
        "required_categories": list(required),
        "env_passthrough": _str_list(raw.get("env_passthrough", []), "env_passthrough"),
        "ai_review": {"mode": mode, "escalate_at": escalate},
        "risk": {"rules": list(rules), "agents": agents, **limits},
        "auto_fix": {"enabled": fix.get("enabled", False), "max_files": max_files,
                     "allowed_paths": _str_list(fix.get("allowed_paths", ["**"]), "auto_fix.allowed_paths"),
                     "forbidden_paths": _str_list(fix.get("forbidden_paths", []), "auto_fix.forbidden_paths")},
        "provenance": {"enforce_tree_unchanged": bool(prov.get("enforce_tree_unchanged", False)),
                       "enforce_clean_tree": bool(prov.get("enforce_clean_tree", False))},
    }
    for name in policy["env_passthrough"]:
        if not ENV_NAME.match(name):
            _fail("env_passthrough contains an invalid variable name: %s" % name)
    return policy, warnings


def policy_relpath(repo: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        raise ValueError("Policy must live inside the repository to be read from the base revision: %s" % path)


def load_policy(repo: Path, value: str, source: str = "worktree",
                base_sha: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    path = Path(value)
    path = (repo / path).resolve() if not path.is_absolute() else path.resolve()
    if source == "base":
        if not base_sha:
            _fail("--policy-source base needs a resolvable base revision")
        rel = policy_relpath(repo, path)
        shown = run_process(["git", "show", "%s:%s" % (base_sha, rel)], repo, 60, env=git_env(), max_output=None)
        if shown["code"] != 0:
            _fail("Policy %s does not exist in base revision %s; --policy-source base cannot be used "
                  "until it is merged." % (rel, base_sha[:12]))
        text = shown["stdout"]
    else:
        if not path.is_file():
            _fail("Policy not found: %s. Copy an examples/policies/*.json profile to .qa/policy.json." % path)
        text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        _fail("Policy is not valid JSON: %s" % exc)
    policy, warnings = normalize_policy(data, repo)
    meta = {"path": str(path), "sha256": sha256_text(text), "source": source,
            "declared_version": policy["version"], "warnings": warnings}
    for check in policy["checks"]:
        for name in check["env_passthrough"] + policy["env_passthrough"]:
            if looks_secret(name):
                meta["warnings"].append("check '%s' receives secret-like variable %s; keep such checks "
                                        "off untrusted PR runs" % (check["name"], name))
    return policy, meta


def policy_diff(head: dict[str, Any], repo: Path, policy_path: Path, base_sha: str) -> dict[str, Any]:
    """Compare the evaluated policy with the one in the base revision (tamper/weakening signal)."""
    result: dict[str, Any] = {"changed": False, "weakened": False, "removed_checks": [],
                              "optional_checks": [], "removed_required_categories": [], "modified_checks": [],
                              "ai_relaxed": False, "note": ""}
    try:
        rel = policy_relpath(repo, policy_path)
    except ValueError:
        result["note"] = "policy outside repository; no base comparison"
        return result
    shown = run_process(["git", "show", "%s:%s" % (base_sha, rel)], repo, 60, env=git_env(), max_output=None)
    if shown["code"] != 0:
        result["changed"], result["note"] = True, "policy not present in base revision (newly introduced)"
        return result
    try:
        base, _ = normalize_policy(json.loads(shown["stdout"]), repo)
    except (ValueError, json.JSONDecodeError) as exc:
        result["changed"], result["note"] = True, "base policy unreadable: %s" % exc
        return result
    head_checks = {c["name"]: c for c in head["checks"]}
    for check in base["checks"]:
        now = head_checks.get(check["name"])
        if now is None:
            result["removed_checks"].append(check["name"])
        else:
            if check["required"] and not now["required"]:
                result["optional_checks"].append(check["name"])
            if check["argv"] != now["argv"] or check["exit_codes"] != now["exit_codes"]:
                result["modified_checks"].append(check["name"])
    result["removed_required_categories"] = sorted(set(base["required_categories"]) - set(head["required_categories"]))
    result["ai_relaxed"] = base["ai_review"]["mode"] == "blocking" and head["ai_review"]["mode"] == "advisory"
    result["weakened"] = bool(result["removed_checks"] or result["optional_checks"]
                              or result["removed_required_categories"] or result["ai_relaxed"])
    result["changed"] = result["weakened"] or bool(result["modified_checks"]) or base != head
    return result


# --------------------------------------------------------------------------- resolutions

def load_resolutions(repo: Path, rel: str = ".qa/resolutions.json",
                     today: date | None = None) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Human-authored, CODEOWNERS-protected decisions. Invalid file = configuration error (fail closed)."""
    today = today or datetime.now(timezone.utc).date()
    path = repo / rel
    if not path.is_file():
        return {}, []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail("%s is not valid JSON: %s" % (rel, exc))
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("resolutions"), list):
        _fail("%s must be {\"version\": 1, \"resolutions\": [...]}" % rel)
    active: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    for i, entry in enumerate(data["resolutions"]):
        where = "%s resolutions[%d]" % (rel, i)
        if not isinstance(entry, dict):
            _fail(where + " must be an object")
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{16}", fingerprint):
            _fail(where + ".fingerprint must be 16 lowercase hex characters")
        if entry.get("decision") not in ("false_positive", "accepted_risk"):
            _fail(where + ".decision must be false_positive or accepted_risk")
        if not isinstance(entry.get("accepted_by"), str) or not entry["accepted_by"].strip():
            _fail(where + ".accepted_by is required")
        if not isinstance(entry.get("reason"), str) or len(entry["reason"].strip()) < 10:
            _fail(where + ".reason must explain the decision (10+ characters)")
        try:
            expires = date.fromisoformat(str(entry.get("expires")))
        except ValueError:
            _fail(where + ".expires must be an ISO date (YYYY-MM-DD)")
        if expires > today + timedelta(days=MAX_RESOLUTION_DAYS):
            _fail("%s.expires may be at most %d days away" % (where, MAX_RESOLUTION_DAYS))
        if expires < today:
            warnings.append("resolution for %s expired on %s; finding is open again" % (fingerprint, expires))
            continue
        active[fingerprint] = {k: entry[k] for k in ("decision", "accepted_by", "reason", "expires")}
    return active, warnings


def load_triage(repo: Path, rel: str = ".qa/triage.json") -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Human triage notes. Validates schema and returns fingerprint -> triage data.
    Triage annotations NEVER change gating or suppress findings.
    Invalid file = configuration error (fail closed).
    """
    path = repo / rel
    if not path.is_file():
        return {}, []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail("%s is not valid JSON: %s" % (rel, exc))
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("triage"), list):
        _fail("%s must be {\"version\": 1, \"triage\": [...]}" % rel)
    active: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    VALID_STATUSES = {"investigating", "confirmed", "wont_fix", "deferred", "needs_info", "comment"}
    for i, entry in enumerate(data["triage"]):
        where = "%s triage[%d]" % (rel, i)
        if not isinstance(entry, dict):
            _fail(where + " must be an object")
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{16}", fingerprint):
            _fail(where + ".fingerprint must be 16 lowercase hex characters")
        status = entry.get("status")
        if status not in VALID_STATUSES:
            _fail(where + ".status must be one of: " + ", ".join(sorted(VALID_STATUSES)))
        triaged_by = entry.get("triaged_by") or entry.get("accepted_by")
        if not isinstance(triaged_by, str) or not triaged_by.strip():
            _fail(where + ".triaged_by is required")
        comment = entry.get("comment") or entry.get("note") or ""
        active[fingerprint] = {
            "status": status,
            "triaged_by": triaged_by.strip(),
            "comment": comment,
            **{k: entry[k] for k in ("ticket", "issue_url", "timestamp", "date") if k in entry}
        }
    return active, warnings


# --------------------------------------------------------------------------- risk

def assess_risk(files: list[str], counts: dict[str, int], policy: dict[str, Any]) -> dict[str, Any]:
    custom = [(r["glob"], r["level"], r.get("reason", "policy rule")) for r in policy["risk"]["rules"]]
    levels: dict[str, tuple[str, str] | None] = {}
    for name in files:
        picked: tuple[str, str] | None = None
        for rules in (custom, DEFAULT_RISK_RULES):
            matches = [(lvl, why) for glob, lvl, why in rules if glob_match(glob, name)]
            if matches:
                picked = max(matches, key=lambda m: LEVELS[m[0]])
                break
        levels[name] = picked
    reasons: list[str] = []
    tier = "low"
    high = sorted((n, v[1]) for n, v in levels.items() if v and v[0] == "high")
    medium = sorted((n, v[1]) for n, v in levels.items() if v and v[0] == "medium")
    code = [n for n, v in levels.items() if not v or v[0] != "low"]
    code_lines = sum(counts.get(n, 0) for n in code)
    lim = policy["risk"]
    if high:
        tier = "high"
        reasons += ["%s (%s)" % (n, why) for n, why in high[:5]]
    elif code_lines >= lim["high_lines"] or len(code) >= lim["high_files"]:
        tier = "high"
        reasons.append("large change: %d lines across %d files" % (code_lines, len(code)))
    elif medium or code_lines >= lim["medium_lines"]:
        tier = "medium"
        reasons += ["%s (%s)" % (n, why) for n, why in medium[:5]]
        if code_lines >= lim["medium_lines"]:
            reasons.append("%d changed lines outside low-risk files" % code_lines)
    elif not files:
        reasons.append("no changed files")
    else:
        reasons.append("small or documentation-only change")
    return {"tier": tier, "reasons": reasons, "changed_files": len(files), "changed_lines": code_lines,
            "agents": lim["agents"][tier]}
