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
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.4.0"
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
    # Windows system essentials (case-insensitively preserved on Windows)
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMDATA",
    "COMMONPROGRAMFILES", "ALLUSERSPROFILE",
}
ENV_ALLOW_PREFIX = ("LC_", "XDG_")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def looks_secret(name: str) -> bool:
    return bool(_SECRET_NAME.search(name))


def scrubbed_env(passthrough: Any = (), extra: dict[str, str] | None = None,
                 source: dict[str, str] | None = None) -> dict[str, str]:
    src = os.environ if source is None else source
    allowed = set(passthrough)
    is_win = os.name == "nt"
    allowed_upper = {k.upper() for k in allowed}
    env_allow_upper = {k.upper() for k in ENV_ALLOW}

    def is_allowed(k: str) -> bool:
        if is_win:
            ku = k.upper()
            return ku in env_allow_upper or any(ku.startswith(p.upper()) for p in ENV_ALLOW_PREFIX) or ku in allowed_upper
        return k in ENV_ALLOW or k.startswith(ENV_ALLOW_PREFIX) or k in allowed

    def is_secret_allowed(k: str) -> bool:
        if not looks_secret(k):
            return True
        return (k.upper() in allowed_upper) if is_win else (k in allowed)

    env = {k: v for k, v in src.items() if is_allowed(k) and is_secret_allowed(k)}
    env.update(extra or {})
    return env


def git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
    })
    return env


# --------------------------------------------------------------------------- processes

def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        elif os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            proc.kill()
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass
        except OSError:
            pass


def _tail(text: str, limit: int | None) -> tuple[str, bool]:
    if limit is None or len(text) <= limit:
        return text, False
    return text[-limit:], True


class UnsupportedShimError(RuntimeError):
    """Raised when a Windows .cmd / .bat shim cannot be safely verified and unwrapped for execution."""


def _is_python_script(path: str) -> bool:
    if path.lower().endswith(".py"):
        return True
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                first = f.readline()
            return first.startswith("#!") and "python" in first.lower()
    except OSError:
        pass
    return False


def _is_node_script(path: str) -> bool:
    if path.lower().endswith((".js", ".cjs", ".mjs")):
        return True
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                first = f.readline()
            return first.startswith("#!") and "node" in first.lower()
    except OSError:
        pass
    return False


def split_cmd_tokens(cmd_str: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    in_quotes = False
    for ch in cmd_str:
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch in (' ', '\t') and not in_quotes:
            if current:
                tokens.append(''.join(current))
                current = []
        else:
            current.append(ch)
    if in_quotes:
        return []
    if current:
        tokens.append(''.join(current))
    return tokens


def apply_cmd_var_subst(val: str, subst_expr: str) -> str:
    """Apply cmd.exe environment variable substitution %VAR:old=new%."""
    m = re.match(r"^%[^:]+:([^=]*)=(.*)%$", subst_expr.strip())
    if m:
        old, new = m.group(1), m.group(2)
        padded = ";" + val.strip(";") + ";"
        replaced = re.sub(re.escape(old), lambda _: new, padded, flags=re.IGNORECASE)
        cleaned = [p for p in replaced.split(";") if p]
        return ";".join(cleaned)
    return val


NON_NATIVE_EXTENSIONS = (
    ".cmd", ".bat", ".js", ".cjs", ".mjs", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".ps1",
)


def _get_env_path_and_pathext(env: dict[str, str] | None) -> tuple[str, str]:
    """Extract PATH and PATHEXT from env, respecting Windows case-insensitivity.

    If env is provided, strictly uses the child environment's values and does NOT
    fall back to the parent process PATH.
    """
    lookup_path: str | None = None
    lookup_pathext: str | None = None

    if env is not None:
        for k, v in env.items():
            k_lower = k.lower()
            if k_lower == "path" and lookup_path is None:
                lookup_path = v
            elif k_lower == "pathext" and lookup_pathext is None:
                lookup_pathext = v
        if lookup_path is None:
            lookup_path = ""
        if lookup_pathext is None:
            lookup_pathext = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"
    else:
        lookup_path = os.environ.get("PATH", "")
        lookup_pathext = os.environ.get(
            "PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"
        )

    return lookup_path, lookup_pathext


def resolve_executable_with_pathext(
    name: str,
    pathext: str | None = None,
    path: str | None = None,
    native_only: bool = False,
) -> str | None:
    """Resolve an executable on PATH respecting modified or explicit PATHEXT semantics.

    If native_only is True, non-native launchers (.cmd, .bat, scripts) are rejected,
    ensuring only directly executable native binaries are returned.
    """
    if path is None:
        path = os.environ.get("PATH", "")
    dirs = [d for d in path.split(os.pathsep) if d]

    if pathext is None:
        pathext = os.environ.get(
            "PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"
        )
    exts = [e.strip() for e in pathext.split(";") if e.strip()]
    if native_only:
        exts = [e for e in exts if e.lower() not in NON_NATIVE_EXTENSIONS]
        if sys.platform == "win32":
            exts = [e for e in exts if e.lower() in (".exe", ".com")]
            if not exts:
                exts = [".exe", ".com"]

    name_lower = name.lower()
    has_ext = any(name_lower.endswith(e.lower()) for e in exts)

    for d in dirs:
        if has_ext:
            cand = os.path.join(d, name)
            if os.path.isfile(cand):
                cand_lower = cand.lower()
                if native_only and cand_lower.endswith(NON_NATIVE_EXTENSIONS):
                    continue
                if (
                    os.access(cand, os.X_OK)
                    or os.name == "nt"
                    or cand_lower.endswith((".exe", ".cmd", ".bat"))
                ):
                    return cand
        else:
            for ext in exts:
                for candidate_ext in (ext, ext.lower()):
                    cand = os.path.join(d, name + candidate_ext)
                    if os.path.isfile(cand):
                        cand_lower = cand.lower()
                        if native_only and cand_lower.endswith(NON_NATIVE_EXTENSIONS):
                            continue
                        if (
                            os.access(cand, os.X_OK)
                            or os.name == "nt"
                            or cand_lower.endswith((".exe", ".cmd", ".bat"))
                        ):
                            return cand

    found = shutil.which(name, path=path)
    if found:
        f_ext = os.path.splitext(found)[1].lower()
        if native_only:
            if f_ext in NON_NATIVE_EXTENSIONS:
                return None
            if sys.platform == "win32" and f_ext not in (".exe", ".com"):
                return None
            if f_ext and f_ext not in (".exe", ".com"):
                return None
        if not f_ext or any(f_ext == e.lower() for e in exts):
            return found
    return None


def _expand_fixed_arg(arg: str, cmd_dir: str) -> str | None:
    """Expand modeled variables (%~dp0, %dp0%) in fixed arguments.

    Fails closed (returns None) if any unmodeled variable (%VAR%, %TEMP%, etc.) remains.
    """
    expanded = arg.replace("%~dp0", cmd_dir + os.sep).replace("%dp0%", cmd_dir + os.sep)
    if "%" in expanded:
        return None
    if "%~dp0" in arg or "%dp0%" in arg:
        if expanded.startswith('"') and expanded.endswith('"') and len(expanded) >= 2:
            expanded = expanded[1:-1]
        elif '="' in expanded and expanded.endswith('"'):
            expanded = expanded.replace('="', '=', 1)[:-1]
        if "=" in expanded:
            prefix, path_part = expanded.split("=", 1)
            expanded = prefix + "=" + os.path.normpath(path_part.replace("\\", os.sep).replace("/", os.sep))
        else:
            expanded = os.path.normpath(expanded.replace("\\", os.sep).replace("/", os.sep))
    elif expanded.startswith('"') and expanded.endswith('"') and len(expanded) >= 2:
        expanded = expanded[1:-1]
    elif '="' in expanded and expanded.endswith('"'):
        expanded = expanded.replace('="', '=', 1)[:-1]
    return expanded


def _unwrap_npm_template(raw_lines: list[str], cmd_dir: str, env: dict[str, str] | None = None) -> list[str] | None:
    """Validate and unwrap the exact genuine npm cmd-shim template and its reachable path."""
    clean = []
    clean_raw = []
    for line in raw_lines:
        line_no_crlf = line.rstrip("\r\n")
        s = line_no_crlf.strip()
        if not s:
            continue
        l = s.lower()
        if l.startswith(("rem ", "rem\t", "::")) or l == "rem":
            if any(ch in s for ch in ("&", "|", "<", ">", "^")):
                return None
            continue
        clean.append(s)
        clean_raw.append(line_no_crlf)

    if not clean:
        return None

    idx = 0
    if clean[idx].lower().lstrip("@").strip() in ("echo off", "echo on"):
        if any(ch in clean[idx] for ch in ("&", "|", "<", ">", "^")):
            return None
        idx += 1

    if idx + 8 > len(clean):
        return None

    if clean[idx].lower() != "goto start":
        return None
    if clean[idx + 1].lower() != ":find_dp0":
        return None
    raw_dp0 = clean_raw[idx + 2].lstrip(" \t@")
    raw_dp0_lower = raw_dp0.lower()
    if not (raw_dp0_lower.startswith(("set ", "set\t")) or raw_dp0_lower.startswith('set"')):
        return None
    var_assign_dp0 = raw_dp0[3:].lstrip(" \t")
    if var_assign_dp0.lower() not in ("dp0=%~dp0", '"dp0=%~dp0"'):
        return None
    if clean[idx + 3].lower().strip() != "exit /b":
        return None
    if clean[idx + 4].lower().strip() != ":start":
        return None
    if clean[idx + 5].lower().strip() != "setlocal":
        return None
    if clean[idx + 6].lower().strip() != "call :find_dp0":
        return None

    idx += 7

    middle = clean[idx:-1]
    middle_raw = clean_raw[idx:-1]
    if not middle:
        return None

    has_if_exist_node = False
    has_set_prog_sibling = False
    has_set_prog_node = False
    pathext_subst: str | None = None
    state = "OUTSIDE"

    for raw_m, mline in zip(middle_raw, middle):
        mlower = mline.lower().strip()
        if any(ch in mline for ch in ("&", "|", "<", ">", "^")):
            return None

        if state == "OUTSIDE":
            if mlower.startswith("if exist "):
                cond_part = mlower[len("if exist "):].strip()
                has_open = False
                if cond_part.endswith("("):
                    has_open = True
                    cond_part = cond_part[:-1].strip()
                cond_target = cond_part.strip("\"'").replace("/", "\\")
                expected_target = (
                    os.path.join(cmd_dir, "node.exe").lower().replace("/", "\\")
                )
                if (
                    cond_target in ("%dp0%\\node.exe", "%~dp0\\node.exe")
                    or cond_target == expected_target
                ):
                    has_if_exist_node = True
                    state = "IN_IF" if has_open else "EXPECT_IF_OPEN"
                    continue
            return None

        elif state == "EXPECT_IF_OPEN":
            if mlower == "(":
                state = "IN_IF"
                continue
            return None

        elif state == "IN_IF":
            if mlower.startswith(("set ", "set\t", "set\"")):
                if has_set_prog_sibling:
                    return None
                raw_set = raw_m.lstrip(" \t@")
                if not raw_set.lower().startswith("set"):
                    return None
                var_raw = raw_set[3:].lstrip(" \t")
                if not (var_raw.startswith('"') and var_raw.endswith('"')):
                    return None
                var = var_raw[1:-1]
                if var.lower().startswith("_prog="):
                    val = var[len("_prog="):]
                    val_norm = val.replace("/", "\\")
                    expected_sibling = (
                        os.path.join(cmd_dir, "node.exe").lower().replace("/", "\\")
                    )
                    if (
                        val_norm.lower() in ("%dp0%\\node.exe", "%~dp0\\node.exe")
                        or val_norm.lower() == expected_sibling
                    ):
                        has_set_prog_sibling = True
                        continue
                    return None
                return None
            if mlower in (") else (", ") else"):
                if not has_set_prog_sibling:
                    return None
                state = "IN_ELSE" if "(" in mlower else "EXPECT_ELSE_OPEN"
                continue
            if mlower == ")":
                state = "EXPECT_ELSE"
                continue
            return None

        elif state == "EXPECT_ELSE":
            if mlower.startswith("else"):
                state = "IN_ELSE" if "(" in mlower else "EXPECT_ELSE_OPEN"
                continue
            return None

        elif state == "EXPECT_ELSE_OPEN":
            if mlower == "(":
                state = "IN_ELSE"
                continue
            return None

        elif state == "IN_ELSE":
            if mlower.startswith(("set ", "set\t", "set\"")):
                raw_set = raw_m.lstrip(" \t@")
                if not raw_set.lower().startswith("set"):
                    return None
                var_raw = raw_set[3:].lstrip(" \t")
                if var_raw.lower().startswith("pathext="):
                    if pathext_subst is not None:
                        return None
                    val_raw = var_raw[len("pathext="):]
                    if val_raw.lower() != "%pathext:;.js;=;%":
                        return None
                    pathext_subst = val_raw
                    continue
                if var_raw.startswith('"') and var_raw.endswith('"'):
                    var = var_raw[1:-1]
                    if var.lower().startswith("_prog="):
                        if has_set_prog_node:
                            return None
                        val = var[len("_prog="):]
                        if val.lower() == "node":
                            has_set_prog_node = True
                            continue
                        return None
                return None
            if mlower == ")":
                state = "DONE"
                continue
            return None

        elif state == "DONE":
            return None

    if state != "DONE" or not (
        has_if_exist_node and has_set_prog_sibling and has_set_prog_node and pathext_subst
    ):
        return None

    sibling_node = os.path.join(cmd_dir, "node.exe")
    if os.path.isfile(sibling_node) and sibling_node.lower().endswith(".exe"):
        node_bin = sibling_node
    else:
        lookup_path, lookup_pathext = _get_env_path_and_pathext(env)
        effective_pathext = apply_cmd_var_subst(lookup_pathext, pathext_subst)
        node_bin = resolve_executable_with_pathext(
            "node", pathext=effective_pathext, path=lookup_path, native_only=True
        )
        if (
            not node_bin
            or not os.path.isfile(node_bin)
            or node_bin.lower().endswith(NON_NATIVE_EXTENSIONS)
        ):
            return None

    inv_line = clean[-1].strip()
    if inv_line.startswith("@"):
        inv_line = inv_line[1:].strip()

    prefix_match = re.match(
        r"^(?:endlocal\s*&\s*goto\s*#_undefined_#\s*2>nul\s*\|\|\s*)?title\s*%comspec%\s*&\s*",
        inv_line,
        re.IGNORECASE,
    )
    if not prefix_match:
        return None

    cmd_part = inv_line[prefix_match.end():].strip()
    if cmd_part.startswith("@"):
        cmd_part = cmd_part[1:].strip()

    if any(ch in cmd_part for ch in ("<", ">", "|", "&", "^")):
        return None

    tokens = split_cmd_tokens(cmd_part)
    if not tokens or tokens[-1] != "%*":
        return None

    prog_tok = tokens[0].strip("\"'").lower()
    if prog_tok != "%_prog%":
        return None

    def expand_token(token: str) -> str:
        clean_tok = token.strip("\"'")
        expanded = clean_tok.replace("%~dp0", cmd_dir + os.sep).replace("%dp0%", cmd_dir + os.sep)
        return os.path.normpath(expanded.replace("\\", os.sep).replace("/", os.sep))

    remaining = tokens[1:-1]
    js_indices = [i for i, t in enumerate(remaining) if _is_node_script(expand_token(t))]
    if len(js_indices) != 1:
        return None
    idx_js = js_indices[0]
    cand_js = expand_token(remaining[idx_js])
    if not os.path.isfile(cand_js) or "%" in cand_js:
        return None

    pre_raw = remaining[:idx_js]
    post_raw = remaining[idx_js + 1:]
    pre_flags = [_expand_fixed_arg(t, cmd_dir) for t in pre_raw]
    post_flags = [_expand_fixed_arg(t, cmd_dir) for t in post_raw]
    if any(t is None for t in pre_flags + post_flags):
        return None

    return [node_bin] + [f for f in pre_flags if f is not None] + [cand_js] + [f for f in post_flags if f is not None]


def unwrap_cmd_shim(cmd_path: str, env: dict[str, str] | None = None) -> list[str] | None:
    """Detect and verify if a Windows .cmd/.bat shim wraps a direct executable, Node.js script, or Python script.

    Only returns [executable, ...fixed_args] if the shim's invocation statement and target can be verified
    with exact argument forwarding (%*). Unrecognized, complex, or unsafe shims return None to fail closed,
    preventing arbitrary command injection and argument corruption via cmd.exe.
    """
    try:
        if not os.path.isfile(cmd_path):
            return None
    except (OSError, ValueError):
        return None

    cmd_dir = os.path.dirname(os.path.abspath(cmd_path))

    try:
        with open(cmd_path, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()
    except OSError:
        return None

    # 1. Try exact validated npm template first
    npm_result = _unwrap_npm_template(raw_lines, cmd_dir, env=env)
    if npm_result is not None:
        return npm_result

    def expand_token(token: str) -> str:
        clean = token.strip("\"'")
        expanded = clean.replace("%~dp0", cmd_dir + os.sep).replace("%dp0%", cmd_dir + os.sep)
        return os.path.normpath(expanded.replace("\\", os.sep).replace("/", os.sep))

    # 2. Straight-line shim parser
    command_lines: list[str] = []

    for line in raw_lines:
        line_no_crlf = line.rstrip("\r\n")
        stripped = line_no_crlf.strip()
        if not stripped:
            continue
        lower = stripped.lower()

        # Reject any shell metacharacters before classifying or ignoring line
        if any(ch in stripped for ch in ("&", "|", "<", ">", "^")):
            return None

        # Ignore comments
        if lower.startswith(("rem ", "rem\t", "::")) or lower == "rem":
            continue

        clean_lower = lower.lstrip("@").strip()

        # Reject any unmodeled control flow
        if (clean_lower.startswith(("goto ", "goto:", "call ", "call:", "exit ", "exit/b", "exit"))
                or stripped.startswith(":")
                or clean_lower.startswith(("if ", "for "))):
            return None

        # Ignore harmless boilerplate
        if clean_lower in ("echo off", "echo on", "setlocal", "endlocal"):
            continue
        if clean_lower.startswith(("echo ", "title ")):
            continue

        # Environment mutations: only harmless exact dp0 definition allowed
        if (
            clean_lower.startswith(("set ", "set\t", "set\"", "set/", "set="))
            or clean_lower == "set"
        ):
            raw_clean = line_no_crlf.lstrip(" \t@")
            raw_clean_lower = raw_clean.lower()
            if not (raw_clean_lower.startswith(("set ", "set\t")) or raw_clean_lower.startswith('set"')):
                return None
            var_assign = raw_clean[3:].lstrip(" \t")
            if var_assign.lower() in ("dp0=%~dp0", '"dp0=%~dp0"'):
                continue
            return None

        # Reject block structures
        if any(ch in clean_lower for ch in ("(", ")")):
            return None

        command_lines.append(stripped)

    # Must have exactly one invocation command in a straight-line shim
    if len(command_lines) != 1:
        return None

    cmd_part = command_lines[0]
    if cmd_part.startswith("@"):
        cmd_part = cmd_part[1:].strip()

    if any(ch in cmd_part for ch in ("<", ">", "|", "&", "^")):
        return None

    tokens = split_cmd_tokens(cmd_part)
    if not tokens or tokens[-1] != "%*":
        return None

    call_tokens = tokens[:-1]
    prog_token = call_tokens[0]
    remaining = call_tokens[1:]
    prog_lower = prog_token.lower().strip("\"'")

    is_explicit = any(sep in prog_token for sep in ("\\", "/")) or prog_token.startswith("%")
    lookup_path, lookup_pathext = _get_env_path_and_pathext(env)

    # A. Node.js wrapper
    if (
        prog_lower in ("node", "node.exe")
        or prog_lower.endswith(("\\node.exe", "/node.exe"))
    ):
        if is_explicit:
            cand = expand_token(prog_token)
            if not os.path.isfile(cand) or cand.lower().endswith(
                NON_NATIVE_EXTENSIONS
            ):
                return None  # Fail closed when explicit interpreter missing/non-native
            node_bin = cand
        else:
            resolved = resolve_executable_with_pathext(
                "node", pathext=lookup_pathext, path=lookup_path, native_only=True
            )
            if (
                not resolved
                or not os.path.isfile(resolved)
                or resolved.lower().endswith(NON_NATIVE_EXTENSIONS)
            ):
                return None
            node_bin = resolved

        js_indices = [
            i for i, t in enumerate(remaining) if _is_node_script(expand_token(t))
        ]
        if len(js_indices) != 1:
            return None
        idx = js_indices[0]
        cand_js = expand_token(remaining[idx])
        if not os.path.isfile(cand_js) or "%" in cand_js:
            return None
        pre_raw = remaining[:idx]
        post_raw = remaining[idx + 1:]
        pre_flags = [_expand_fixed_arg(t, cmd_dir) for t in pre_raw]
        post_flags = [_expand_fixed_arg(t, cmd_dir) for t in post_raw]
        if any(t is None for t in pre_flags + post_flags):
            return None
        return (
            [node_bin]
            + [f for f in pre_flags if f is not None]
            + [cand_js]
            + [f for f in post_flags if f is not None]
        )

    # B. Python wrapper
    if "python" in os.path.basename(prog_lower):
        if is_explicit:
            cand_py = expand_token(prog_token)
            if not os.path.isfile(cand_py) or cand_py.lower().endswith(
                NON_NATIVE_EXTENSIONS
            ):
                return None  # Fail closed when explicit interpreter missing/non-native
            py_bin = cand_py
        else:
            resolved = resolve_executable_with_pathext(
                "python", pathext=lookup_pathext, path=lookup_path, native_only=True
            )
            if (
                not resolved
                and env is None
                and "python" in sys.executable.lower()
                and os.path.isfile(sys.executable)
                and not sys.executable.lower().endswith(NON_NATIVE_EXTENSIONS)
            ):
                resolved = sys.executable
            if (
                not resolved
                or not os.path.isfile(resolved)
                or resolved.lower().endswith(NON_NATIVE_EXTENSIONS)
            ):
                return None
            py_bin = resolved

        py_indices = [
            i for i, t in enumerate(remaining) if _is_python_script(expand_token(t))
        ]
        if len(py_indices) != 1:
            return None
        idx = py_indices[0]
        cand_script = expand_token(remaining[idx])
        if not os.path.isfile(cand_script) or "%" in cand_script:
            return None
        pre_raw = remaining[:idx]
        post_raw = remaining[idx + 1:]
        pre_flags = [_expand_fixed_arg(t, cmd_dir) for t in pre_raw]
        post_flags = [_expand_fixed_arg(t, cmd_dir) for t in post_raw]
        if any(t is None for t in pre_flags + post_flags):
            return None
        return (
            [py_bin]
            + [f for f in pre_flags if f is not None]
            + [cand_script]
            + [f for f in post_flags if f is not None]
        )

    # C. Direct executable
    if prog_lower.endswith(".exe"):
        if is_explicit:
            cand_exe = expand_token(prog_token)
            if (
                not os.path.isfile(cand_exe)
                or cand_exe.lower() == os.path.abspath(cmd_path).lower()
                or cand_exe.lower().endswith(NON_NATIVE_EXTENSIONS)
            ):
                return None
        else:
            resolved = resolve_executable_with_pathext(
                prog_token, pathext=lookup_pathext, path=lookup_path, native_only=True
            )
            if (
                not resolved
                or not os.path.isfile(resolved)
                or resolved.lower() == os.path.abspath(cmd_path).lower()
                or resolved.lower().endswith(NON_NATIVE_EXTENSIONS)
            ):
                return None
            cand_exe = resolved
        fixed = [_expand_fixed_arg(t, cmd_dir) for t in remaining]
        if any(t is None for t in fixed):
            return None
        return [cand_exe] + [f for f in fixed if f is not None]

    return None


def resolve_argv_windows(
    argv: list[str], env: dict[str, str] | None = None
) -> list[str]:
    """On Windows, resolve .cmd / .bat shims into direct executable arguments without shell injection.

    Raises UnsupportedShimError if the wrapper cannot be safely verified and unwrapped.
    """
    if os.name != "nt" or not argv:
        return argv
    prog = argv[0]
    lookup_path, lookup_pathext = _get_env_path_and_pathext(env)
    resolved = (
        shutil.which(prog, path=lookup_path)
        or resolve_executable_with_pathext(prog, pathext=lookup_pathext, path=lookup_path)
        or prog
    )
    lower = resolved.lower()
    if lower.endswith((".cmd", ".bat")):
        unwrapped = unwrap_cmd_shim(resolved, env=env)
        if unwrapped:
            return unwrapped + argv[1:]
        raise UnsupportedShimError(
            f"cannot safely execute Windows batch shim '{resolved}': "
            "unsupported or unrecognized wrapper format (shell fallback disabled for security)"
        )
    if resolved != prog:
        return [resolved] + argv[1:]
    return argv


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
        cmd_argv = resolve_argv_windows(argv, env=env)
    except UnsupportedShimError as exc:
        return result(126, "", str(exc))

    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    try:
        proc = subprocess.Popen(
            cmd_argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
            start_new_session=(os.name == "posix"), creationflags=creationflags)
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
        cmd_argv = resolve_argv_windows(argv, env=env)
    except UnsupportedShimError as exc:
        return {"code": 126, "stdout": "", "stderr": str(exc), "timed_out": False,
                "truncated": False, "output_limit_exceeded": False,
                "duration_seconds": round(time.monotonic() - started, 3)}

    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    try:
        proc = subprocess.Popen(
            cmd_argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"), creationflags=creationflags)
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


def compute_tree_provenance(repo: Path, exclude_dir: Path | None = None) -> dict[str, Any]:
    """Compute working-tree provenance fingerprint using aqa-tree-v1.

    Identifies observed working-tree bytes, not an immutable filesystem snapshot
    or a cryptographic attestation. Encodes working-tree state into an unambiguous,
    canonical, length-prefixed format before computing SHA-256.

    Accounts for staged changes, unstaged changes, untracked non-ignored files,
    deletions, symlinks (without following outside repository scope), binary files,
    and filenames containing spaces, newlines, colons, or unicode surrogates.
    """
    try:
        head_res = run_process(["git", "rev-parse", "HEAD"], repo, 30, env=git_env(), max_output=None)
        head_sha = head_res["stdout"].strip() if head_res["code"] == 0 else "unborn"

        tree_res = run_process(["git", "rev-parse", "HEAD^{tree}"], repo, 30, env=git_env(), max_output=None)
        head_tree_sha = tree_res["stdout"].strip() if tree_res["code"] == 0 else ""

        status_raw = git_raw(repo, "-c", "core.quotepath=false", "status", "--porcelain=v1", "-z", "--untracked-files=all")
    except Exception as exc:
        raise ValueError("Failed to compute working tree provenance: %s" % exc) from exc

    exclude_prefix = _relative_out(repo, exclude_dir)
    tokens = status_raw.split("\0")
    i = 0
    entries: list[tuple[str, str, str, str]] = []

    while i < len(tokens):
        item = tokens[i]
        if not item:
            i += 1
            continue
        if len(item) < 3:
            i += 1
            continue
        xy = item[:2]
        path = item[3:]
        i += 1
        if xy.startswith("R") and i < len(tokens):
            i += 1  # skip rename orig_path

        if exclude_prefix:
            if path == exclude_prefix or path.startswith(exclude_prefix + "/"):
                continue

        p = repo / path
        try:
            if p.is_symlink():
                kind = "symlink"
                target = os.readlink(p)
                content_id = "target:" + sha256_text(target)
            elif p.is_file():
                kind = "file"
                content_id = "sha256:" + sha256_file(p)
            elif p.is_dir():
                kind = "directory"
                content_id = "dir"
            else:
                kind = "deleted"
                content_id = "missing"
        except (OSError, PermissionError) as exc:
            raise ValueError("Failed to read working tree file '%s' for provenance: %s" % (path, exc)) from exc

        entries.append((path, xy, kind, content_id))

    def path_key(entry: tuple[str, str, str, str]) -> bytes:
        return entry[0].encode("utf-8", "surrogateescape")

    entries.sort(key=path_key)

    def field(data: str | bytes) -> bytes:
        raw = data.encode("utf-8", "surrogateescape") if isinstance(data, str) else data
        return str(len(raw)).encode("ascii") + b":" + raw

    stream = bytearray()
    stream.extend(b"aqa-tree-v1\n")
    stream.extend(b"head\n" + field(head_sha) + b"\n")
    stream.extend(b"tree\n" + field(head_tree_sha) + b"\n")
    for path, xy, kind, content_id in entries:
        stream.extend(b"entry\n"
                      + field(xy) + b"\n"
                      + field(path) + b"\n"
                      + field(kind) + b"\n"
                      + field(content_id) + b"\n")

    digest = hashlib.sha256(stream).hexdigest()
    return {
        "algorithm": "aqa-tree-v1",
        "fingerprint": "aqa-tree-v1:" + digest,
        "head_sha": head_sha,
        "head_tree_sha": head_tree_sha,
        "entry_count": len(entries),
        "canonical_sha256": digest,
    }


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
