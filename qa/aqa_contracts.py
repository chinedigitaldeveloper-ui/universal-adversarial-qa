"""CLI contracts: real-binary version/flag probes and runtime output validation."""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from aqa_core import run_process, validate_json

HERE = Path(__file__).resolve().parent
CONTRACT_DIR = HERE / "contracts"


def load_contracts(path: Path | None = None) -> dict[str, Any]:
    data = json.loads((path or CONTRACT_DIR / "cli.json").read_text(encoding="utf-8"))
    if data.get("contract_version") != 1 or not isinstance(data.get("tools"), dict):
        raise ValueError("Unsupported CLI contract file")
    return data


def parse_version(text: str, regex: str) -> tuple[int, ...] | None:
    match = re.search(regex, text)
    if not match:
        return None
    try:
        return tuple(int(x) for x in match.group(1).split("."))
    except ValueError:
        return None


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def has_flag(text: str, flag: str) -> bool:
    return bool(re.search(r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])", text))


def verify_tool(name: str, contracts: dict[str, Any], cwd: Path, timeout: int = 30) -> dict[str, Any]:
    """Probe the REAL executable: presence, version floor, and the flags aqa.py actually passes.

    Needs no authentication and spends no model tokens (it only runs --version and --help).
    status: ok | missing | violated | unverifiable
    """
    spec = contracts["tools"][name]
    result: dict[str, Any] = {"tool": name, "executable": spec["executable"], "path": None, "status": "ok",
                              "version": None, "min_version": spec["version"].get("min"),
                              "probes": [], "reasons": []}
    path = shutil.which(spec["executable"])
    if not path:
        result.update(status="missing", reasons=["executable '%s' is not installed or not on PATH" % spec["executable"]])
        return result
    result["path"] = path
    ver = run_process(spec["version"]["argv"], cwd, timeout)
    text = ver["stdout"] + "\n" + ver["stderr"]
    version = parse_version(text, spec["version"]["regex"]) if ver["code"] == 0 else None
    if version is None:
        if spec["version"].get("min"):
            result["status"] = "unverifiable"
            result["reasons"].append("could not determine version (exit %s); floor %s is enforced"
                                     % (ver["code"], spec["version"]["min"]))
        else:
            result["reasons"].append("version not parseable; no floor is enforced for %s" % name)
    else:
        result["version"] = ".".join(str(x) for x in version)
        floor = spec["version"].get("min")
        if floor and _cmp(version, tuple(int(x) for x in floor.split("."))) < 0:
            result["status"] = "violated"
            result["reasons"].append("version %s is older than required %s" % (result["version"], floor))
    for probe in spec.get("probes", []):
        out = run_process(probe["argv"], cwd, timeout)
        combined = out["stdout"] + "\n" + out["stderr"]
        missing = [f for f in probe["must_contain"] if not has_flag(combined, f)]
        ok = out["code"] == 0 and not missing
        result["probes"].append({"name": probe["name"], "ok": ok, "exit_code": out["code"], "missing": missing})
        if not ok:
            if result["status"] == "ok":
                result["status"] = "violated" if out["code"] == 0 else "unverifiable"
            result["reasons"].append(
                "probe '%s': %s" % (probe["name"], ("missing flags " + ", ".join(missing)) if missing
                                    else "command exited %s" % out["code"]))
    return result


def validate_coderabbit_events(events: list[dict[str, Any]]) -> list[str]:
    schemas = json.loads((CONTRACT_DIR / "coderabbit-events.json").read_text(encoding="utf-8"))
    violations: list[str] = []
    for index, event in enumerate(events):
        kind = event.get("type")
        if kind in ("finding", "complete"):
            violations += ["event %d %s" % (index, v) for v in validate_json(event, schemas[kind])]
    if not any(e.get("type") == "complete" for e in events):
        violations.append("stream has no 'complete' event")
    return violations[:20]


def validate_against_schema_file(instance: Any, schema_path: Path) -> list[str]:
    return validate_json(instance, json.loads(schema_path.read_text(encoding="utf-8")))[:20]
