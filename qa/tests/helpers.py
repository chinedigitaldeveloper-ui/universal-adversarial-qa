"""Hermetic fixtures: throwaway Git repos, fake AI CLIs on a restricted PATH. No provider accounts."""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

QA = Path(__file__).resolve().parents[1]
SCRIPT = QA / "aqa.py"
sys.path.insert(0, str(QA))

import aqa_core  # noqa: E402
from aqa_core import validate_json  # noqa: E402

PY = sys.executable


def sh(cwd: Path, *args: str) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()


def passing_check(name: str = "unit", category: str = "test", **extra: Any) -> dict[str, Any]:
    return {"name": name, "category": category, "argv": [PY, "-c", "pass"], **extra}


def policy_v2(checks: list | None = None, **extra: Any) -> dict[str, Any]:
    return {"version": 2, "name": "test", "required_categories": ["test"],
            "checks": checks if checks is not None else [passing_check()], **extra}


def setup_repo(root: Path, policy: dict[str, Any] | None = None, change: str = "demo.txt") -> None:
    sh(root, "git", "init", "-q", "-b", "main")
    sh(root, "git", "config", "user.email", "test@example.invalid")
    sh(root, "git", "config", "user.name", "Test")
    (root / ".qa").mkdir(exist_ok=True)
    (root / ".qa" / "policy.json").write_text(json.dumps(policy if policy is not None else policy_v2()), encoding="utf-8")
    (root / ".gitignore").write_text(".qa/out/\n", encoding="utf-8")
    (root / "demo.txt").write_text("baseline\n", encoding="utf-8")
    sh(root, "git", "add", ".")
    sh(root, "git", "commit", "-qm", "baseline")
    sh(root, "git", "switch", "-qc", "feature")
    target = root / change
    target.parent.mkdir(parents=True, exist_ok=True)
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    target.write_text(existing + "change\n", encoding="utf-8")
    sh(root, "git", "add", ".")
    sh(root, "git", "commit", "-qm", "change")


def commit_all(root: Path, message: str = "more") -> None:
    sh(root, "git", "add", "-A")
    sh(root, "git", "commit", "-qm", message)


def hermetic_path(tmp: Path, bindir: Path | None = None) -> str:
    """PATH containing only git, python and (optionally) fake tools; no real codex/coderabbit can leak in."""
    base = tmp / "_sysbin"
    if not base.exists():
        base.mkdir()
        (base / "git").symlink_to(shutil.which("git"))
        for name in ("python", "python3"):
            (base / name).symlink_to(PY)
    parts = ([str(bindir)] if bindir else []) + [str(base)]
    return os.pathsep.join(parts)


_VERSION_HELP = r'''#!{py}
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
log = os.environ.get("AQA_FAKE_LOG")
if log and args[:1] not in (["--version"],) and "--help" not in args:
    with open(log, "a") as handle:
        handle.write("{name} " + " ".join(args[:3]) + "\n")
if args[:1] == ["--version"]:
    print("{version_line}"); sys.exit(0)
if "--help" in args:
    print("{help_text}"); sys.exit(0)
{body}
'''

CODEX_HELP = "Options:\\n  --ephemeral\\n  --sandbox <MODE>\\n  --ignore-user-config\\n  --ignore-rules\\n  --output-schema <FILE>\\n  -o, --output-last-message <FILE>"
CODEX_BODY = r'''
out = Path(args[args.index("-o") + 1])
prompt = args[-1]
{behavior}
'''
CR_HELP = "Options:\\n  --agent\\n  --gate <level>\\n  --base-commit <sha>\\n  --include-untracked"

CODEX_CLEAN = r'''
if "codex-fix" in str(out):
    out.write_text("no-op")
elif "verification" in str(out):
    allegations = json.loads(prompt.split("Untrusted allegations to check:\n")[-1])
    out.write_text(json.dumps({"assessments": [{"id": f["id"], "verdict": "confirmed", "evidence": "mock", "recommended_action": "fix"} for f in allegations]}))
else:
    out.write_text(json.dumps({"summary": "mock review", "findings": []}))
'''

CR_CLEAN = r'''
print(json.dumps({"type": "complete", "status": "review_completed", "outcome": "completed", "unreviewedFileCount": 0,
                  "gate": {"status": "passed", "threshold": "major"}}))
'''

CR_FINDING_WHILE_CHANGED = r'''
vulnerable = "change" in Path("demo.txt").read_text()
if vulnerable:
    print(json.dumps({"type": "finding", "severity": "major", "fileName": "demo.txt", "startLine": 2, "title": "Needs fix", "comment": "mock proof"}))
print(json.dumps({"type": "complete", "status": "review_completed", "outcome": "completed", "unreviewedFileCount": 0,
                  "gate": {"status": "blocked" if vulnerable else "passed", "threshold": "major"}}))
sys.exit(2 if vulnerable else 0)
'''


def write_exe(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def fake_codex(bindir: Path, behavior: str = CODEX_CLEAN, version: str = "codex-cli 0.77.0", help_text: str = CODEX_HELP) -> None:
    body = CODEX_BODY.format(behavior=behavior)
    write_exe(bindir / "codex", _VERSION_HELP.format(py=PY, name="codex", version_line=version, help_text=help_text, body=body))


def fake_coderabbit(bindir: Path, behavior: str = CR_CLEAN, version: str = "0.9.5", help_text: str = CR_HELP) -> None:
    write_exe(bindir / "coderabbit", _VERSION_HELP.format(py=PY, name="coderabbit", version_line=version, help_text=help_text, body=behavior))


class Harness(unittest.TestCase):
    """Per-test temp dir, hermetic environment, and helpers to run aqa.py as a real subprocess."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.fake_log = self.tmp / "fake.log"

    def env(self, **extra: str) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if k not in ("CI", "GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY")}
        env["PATH"] = hermetic_path(self.tmp, self.bin)
        env["AQA_FAKE_LOG"] = str(self.fake_log)
        env.update(extra)
        return env

    def aqa(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([PY, str(SCRIPT), *args], capture_output=True, text=True, env=env or self.env(), cwd=self.repo)

    def ci(self, *extra: str, **env: str) -> subprocess.CompletedProcess:
        return self.aqa("ci", "--repo", str(self.repo), "--base", "main", *extra, env=self.env(**env))

    def review(self, *extra: str, **env: str) -> subprocess.CompletedProcess:
        return self.aqa("review", "--repo", str(self.repo), "--base", "main", *extra, env=self.env(**env))

    def report(self) -> dict[str, Any]:
        return json.loads((self.repo / ".qa" / "out" / "report.json").read_text(encoding="utf-8"))

    def invoked(self) -> list[str]:
        return self.fake_log.read_text().splitlines() if self.fake_log.exists() else []

    def assert_valid_report(self) -> dict[str, Any]:
        report = self.report()
        schema = json.loads((QA / "schema" / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_json(report, schema), [])
        return report
