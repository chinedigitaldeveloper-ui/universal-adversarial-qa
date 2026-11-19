"""Shared primitives for the portable QA runner (stdlib only).

Execution semantics owned by the orchestrator, not by repositories:
  * process execution with whole-process-group timeout kill
  * environment scrubbing for repository-controlled commands
  * secret redaction for everything written to disk
  * exit codes, severity ordering, git helpers, a small JSON-schema validator
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.3.0"
SEVERITY = {"none": 0, "info": 1, "trivial": 2, "minor": 3, "major": 4, "critical": 5}
EXIT_PASSED, EXIT_FAILED, EXIT_INCOMPLETE, EXIT_ESCALATED = 0, 2, 3, 4
MAX_OUTPUT = 30000
MAX_CHECK_TIMEOUT = 3600


def emit(message: str) -> None:
    """Progress output. Untrusted text (file names, check names, AI titles) reaches here, so a message can
    never span lines or begin with '::': CI log parsers would execute such a line as a workflow command."""
    message = message.replace("\r", "\\r").replace("\n", "\\n")
    if message.lstrip().startswith("::"):  # runners trim leading whitespace before matching, so use a visible marker
        message = "> " + message
    print(message, flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- redaction

_SECRET_NAME = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|SIGNING_?KEY)", re.I)
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), "[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "[REDACTED]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}"), "[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=\-]{20,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b((?:api|access|secret|auth)[_-]?(?:key|token)|token|password|passwd|secret)"
                r"(\s*[:=]\s*[\"']?)[A-Za-z0-9_\-./+=]{12,}"), r"\1\2[REDACTED]"),
]


def secret_values() -> list[str]:
    """Exact values of secret-looking environment variables in THIS process."""
    values = {v for k, v in os.environ.items() if _SECRET_NAME.search(k) and len(v) >= 8}
    return sorted(values, key=len, reverse=True)


def redact(text: str) -> str:
    for value in secret_values():
        text = text.replace(value, "[REDACTED]")
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [redact_obj(x) for x in value]
    if isinstance(value, dict):
        return {k: redact_obj(v) for k, v in value.items()}
    return value


def save(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact(content), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(redact_obj(value), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------- environment

# Repository-controlled commands get an ALLOWLISTED environment. Provider keys, CI tokens
# and cloud credentials are not inherited unless a policy names them in env_passthrough.
ENV_ALLOW = {
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "TERM", "TZ",
    "TMPDIR", "TEMP", "TMP", "CI", "GITHUB_ACTIONS", "GITHUB_WORKSPACE", "GITHUB_SHA",
    "GITHUB_REF", "GITHUB_BASE_REF", "GITHUB_HEAD_REF", "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY",
    "RUNNER_OS", "RUNNER_ARCH", "RUNNER_TEMP", "RUNNER_TOOL_CACHE",
    "JAVA_HOME", "GOROOT", "GOPATH", "GOFLAGS", "GOCACHE", "GOMODCACHE", "CARGO_HOME", "RUSTUP_HOME",
    "PUB_CACHE", "FLUTTER_ROOT", "NVM_DIR", "PYENV_ROOT", "VIRTUAL_ENV", "PYTHONPATH", "PYTHONUTF8",
    "NODE_PATH", "DOTNET_ROOT", "ANDROID_HOME", "ANDROID_SDK_ROOT",
    "SYSTEMROOT", "PATHEXT", "COMSPEC", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES",
}
ENV_ALLOW_PREFIX = ("LC_", "XDG_")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def looks_secret(name: str) -> bool:
    return bool(_SECRET_NAME.search(name))


def scrubbed_env(passthrough: Any = (), extra: dict[str, str] | None = None,
                 source: dict[str, str] | None = None) -> dict[str, str]:
    src = os.environ if source is None else source
    allowed = set(passthrough)
    env = {k: v for k, v in src.items()
           if (k in ENV_ALLOW or k.startswith(ENV_ALLOW_PREFIX) or k in allowed)
           and (not looks_secret(k) or k in allowed)}
    env.update(extra or {})
    return env


def git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    return env


# --------------------------------------------------------------------------- processes

def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _tail(text: str, limit: int | None) -> tuple[str, bool]:
    if limit is None or len(text) <= limit:
        return text, False
    return text[-limit:], True


def run_process(argv: list[str], cwd: Path, seconds: int = 600, env: dict[str, str] | None = None,
                max_output: int | None = MAX_OUTPUT) -> dict[str, Any]:
    """Run argv with stdin closed, in its own process group; kill the WHOLE group on timeout."""
    started = time.monotonic()

    def result(code: int, out: str, err: str, timed_out: bool = False) -> dict[str, Any]:
        out, t1 = _tail(out, max_output)
        err, t2 = _tail(err, max_output)
        return {"code": code, "stdout": out, "stderr": err, "timed_out": timed_out,
                "truncated": t1 or t2, "duration_seconds": round(time.monotonic() - started, 3)}

    try:
        proc = subprocess.Popen(
            argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, errors="replace",
            start_new_session=(os.name == "posix"))
    except FileNotFoundError as exc:
        return result(127, "", str(exc))
    except OSError as exc:
        return result(126, "", str(exc))
    try:
        out, err = proc.communicate(timeout=seconds)
        return result(proc.returncode, out or "", err or "")
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:  # a grandchild escaped the group and holds the pipes
            out, err = "", ""
        return result(124, out or "", "Timed out after %ds. %s" % (seconds, err or ""), timed_out=True)


# A complete review stream must never be silently tailed. Unlike run_process's
# human-readable log capture, this consumes both pipes concurrently, retaining
# complete output UP TO strict byte limits. Breaching either limit kills the
# subprocess group and marks the evidence incomplete. No unbounded communicate().
def run_process_bounded(argv: list[str], cwd: Path, seconds: int = 600,
                        env: dict[str, str] | None = None, stdout_limit: int = 8 * 1024 * 1024,
                        stderr_limit: int = 512 * 1024) -> dict[str, Any]:
    """Run a structured-output tool with bounded memory and a complete-or-incomplete result.

    Separate reader threads make this portable to Windows (selectors cannot watch
    subprocess pipes there). Retained output is capped; oversized streams terminate
    the child rather than letting a synthetic completion event hide lost findings.
    """
    if stdout_limit < 1 or stderr_limit < 1:
        raise ValueError("bounded output limits must be positive")
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"))
    except (FileNotFoundError, OSError) as exc:
        return {"code": 127 if isinstance(exc, FileNotFoundError) else 126,
                "stdout": "", "stderr": str(exc), "timed_out": False, "truncated": False,
                "output_limit_exceeded": False,
                "duration_seconds": round(time.monotonic() - started, 3)}

    exceeded = threading.Event()
    buffers: list[bytearray] = [bytearray(), bytearray()]

    def reader(pipe: Any, output: bytearray, limit: int) -> None:
        try:
            while True:
                chunk = pipe.read1(65536)
                if not chunk:
                    break
                remaining = limit - len(output)
                if len(chunk) > remaining:
                    if remaining > 0:
                        output.extend(chunk[:remaining])
                    exceeded.set()
                    break
                output.extend(chunk)
        finally:
            pipe.close()

    workers = [threading.Thread(target=reader, args=(proc.stdout, buffers[0], stdout_limit), daemon=True),
               threading.Thread(target=reader, args=(proc.stderr, buffers[1], stderr_limit), daemon=True)]
    for worker in workers:
        worker.start()

    timed_out = False
    deadline = started + seconds
    while proc.poll() is None:
        if exceeded.is_set():
            _kill_tree(proc)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _kill_tree(proc)
            break
        time.sleep(0.025)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
    for worker in workers:
        worker.join(timeout=1)
    incomplete_capture = exceeded.is_set() or any(worker.is_alive() for worker in workers)
    return {"code": 124 if timed_out else proc.returncode,
            "stdout": buffers[0].decode("utf-8", "replace"),
            "stderr": buffers[1].decode("utf-8", "replace"),
            "timed_out": timed_out, "truncated": incomplete_capture,
            "output_limit_exceeded": exceeded.is_set(),
            "duration_seconds": round(time.monotonic() - started, 3)}


# --------------------------------------------------------------------------- git

def git_raw(repo: Path, *args: str) -> str:
    response = run_process(["git", *args], repo, seconds=60, env=git_env(), max_output=None)
    if response["code"] != 0:
        raise ValueError("git %s: %s" % (" ".join(args), response["stderr"].strip()))
    return response["stdout"]


def git(repo: Path, *args: str) -> str:
    return git_raw(repo, *args).strip()


def resolve_base(repo: Path, base: str) -> tuple[str, str, str]:
    """Return (base_sha, merge_base_sha, warning). All reviewers and checks use merge_base."""
    base_sha = git(repo, "rev-parse", "--verify", base + "^{commit}")
    response = run_process(["git", "merge-base", base_sha, "HEAD"], repo, 60, env=git_env(), max_output=None)
    if response["code"] == 0 and response["stdout"].strip():
        return base_sha, response["stdout"].strip(), ""
    return base_sha, base_sha, "No merge-base with HEAD (shallow clone?); diffing against the base commit directly."


def _relative_out(repo: Path, out: Path | None) -> str | None:
    if out is None:
        return None
    try:
        return out.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return None


def changed_files(repo: Path, base: str, exclude_dir: Path | None = None) -> list[str]:
    tracked = git_raw(repo, "diff", "--name-only", "-z", base)
    untracked = git_raw(repo, "ls-files", "-z", "--others", "--exclude-standard")
    names = {x for x in (tracked + "\0" + untracked).split("\0") if x}
    prefix = _relative_out(repo, exclude_dir)
    if prefix:
        names = {n for n in names if not (n == prefix or n.startswith(prefix + "/"))}
    return sorted(names)


def diff_numstat(repo: Path, base: str, files: list[str]) -> dict[str, int]:
    """Changed line count (added + deleted) per file, including small untracked text files."""
    counts: dict[str, int] = {}
    text = git_raw(repo, "-c", "core.quotepath=false", "diff", "--numstat", "--no-renames", base)
    for line in text.splitlines():
        parts = line.split("\t", 2)
        if len(parts) == 3:
            a, d, name = parts
            counts[name] = (int(a) if a.isdigit() else 1) + (int(d) if d.isdigit() else 1)
    for name in files:
        if name in counts:
            continue
        path = repo / name
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 1_000_000:
            try:
                counts[name] = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
            except OSError:
                counts[name] = 1
        else:
            counts[name] = 1
    return counts


def file_digests(repo: Path, paths: list[str]) -> dict[str, str]:
    """Digest actual working-tree bytes per path (symlink targets and missing files included)."""
    digests: dict[str, str] = {}
    for name in sorted(set(paths)):
        path = repo / name
        if path.is_symlink():
            digests[name] = "symlink:" + os.readlink(path)
        elif path.is_file():
            digests[name] = "file:" + sha256_file(path)
        else:
            digests[name] = "missing"
    return digests


# --------------------------------------------------------------------------- JSON schema (subset)

def _is_type(value: Any, kind: str) -> bool:
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "null":
        return value is None
    return False


def validate_json(value: Any, schema: dict[str, Any], root: dict[str, Any] | None = None,
                  path: str = "$") -> list[str]:
    """Validate against the JSON-Schema subset used by qa/schema and qa/contracts. Returns errors."""
    root = root or schema
    if "$ref" in schema:
        node: Any = root
        for part in schema["$ref"].lstrip("#/").split("/"):
            node = node[part]
        return validate_json(value, node, root, path)
    errors: list[str] = []
    kinds = schema.get("type")
    if kinds is not None:
        kinds = [kinds] if isinstance(kinds, str) else kinds
        if not any(_is_type(value, k) for k in kinds):
            return ["%s: expected %s, got %s" % (path, "|".join(kinds), type(value).__name__)]
    if "enum" in schema and value not in schema["enum"]:
        errors.append("%s: %r not in %s" % (path, value, schema["enum"]))
    if "const" in schema and value != schema["const"]:
        errors.append("%s: expected constant %r" % (path, schema["const"]))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append("%s: %r below minimum %r" % (path, value, schema["minimum"]))
        if "maximum" in schema and value > schema["maximum"]:
            errors.append("%s: %r above maximum %r" % (path, value, schema["maximum"]))
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append("%s: shorter than %d" % (path, schema["minLength"]))
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append("%s: does not match %s" % (path, schema["pattern"]))
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append("%s: missing required '%s'" % (path, key))
        props = schema.get("properties", {})
        for key, item in value.items():
            if key in props:
                errors += validate_json(item, props[key], root, "%s.%s" % (path, key))
            elif schema.get("additionalProperties") is False:
                errors.append("%s: unexpected property '%s'" % (path, key))
            elif isinstance(schema.get("additionalProperties"), dict):
                errors += validate_json(item, schema["additionalProperties"], root, "%s.%s" % (path, key))
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append("%s: fewer than %d items" % (path, schema["minItems"]))
        if "items" in schema:
            for index, item in enumerate(value):
                errors += validate_json(item, schema["items"], root, "%s[%d]" % (path, index))
    return errors
