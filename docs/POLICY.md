# Policy reference (`.qa/policy.json`, version 2)

Unknown keys are **errors** (a typo like `required_categorys` must not silently weaken the gate).

```json
{
  "version": 2,
  "name": "my-service",
  "required_categories": ["test", "lint"],
  "env_passthrough": [],
  "checks": [
    {"name": "pytest", "category": "test", "argv": ["python", "-m", "pytest", "-q"], "timeout_seconds": 1800},
    {"name": "gitleaks", "category": "secrets", "required": false,
     "argv": ["gitleaks", "detect", "--source", ".", "--redact", "--log-opts={base}..HEAD"],
     "exit_codes": {"pass": [0], "fail": [1]}}
  ],
  "ai_review": {"mode": "advisory", "escalate_at": "major"},
  "risk": {"rules": [{"glob": "services/ledger/**", "level": "high", "reason": "money movement"}],
           "agents": {"low": "none", "medium": "coderabbit", "high": "both"},
           "medium_lines": 40, "high_lines": 500, "high_files": 20},
  "auto_fix": {"enabled": false, "max_files": 10, "allowed_paths": ["**"], "forbidden_paths": []}
}
```

| Field | Meaning |
|---|---|
| `required_categories` | categories that need at least one **required** check; otherwise `INCOMPLETE`. Default `["test"]`. Categories: `format lint types test build sast secrets deps other` |
| `checks[].argv` | argument vector (no shell). `{base}` = merge-base SHA, `{repo}` = repository path |
| `checks[].required` | default `true`. A missing required tool is `INCOMPLETE`; a missing optional tool is `skipped` with a warning; an installed optional tool that reports problems still **fails** |
| `checks[].exit_codes` | `pass` (default `[0]`) and optional `fail`; other codes are tool errors (`INCOMPLETE`) when `fail` is declared |
| `checks[].cwd` | relative directory inside the repo (monorepos); one policy can run several packages |
| `checks[].env`, `env_passthrough` | static non-secret variables; names re-allowed from the (otherwise scrubbed) environment |
| `ai_review.mode` | `advisory` (default): AI never changes the gate. `blocking`: v0.1 behavior, findings >= `escalate_at` fail and incomplete reviewers make it `incomplete` |
| `ai_review.escalate_at` | severity from which a finding is escalated (and the CodeRabbit `--gate` threshold) |
| `risk` | see `docs/CONTRACTS.md`; custom rules override the built-in ones for matching files |
| `auto_fix` | off by default. See README "What the AI pipeline is allowed to do" |

`version: 1` policies still load (AI stays `blocking`, no required categories) with a deprecation warning.

## Choosing where the policy comes from

* `--policy-source worktree` (default for **local CLI only**): the PR's own policy. Changes to it are escalated, and removing checks or categories is flagged
  as *policy weakened*.
* `--policy-source base`: the policy at the base commit decides the gate, so a PR cannot weaken the gate that judges it. Use it once the
  policy is merged. **Every supplied production PR workflow and the central action default to `base`.**
  The initial bootstrap PR cannot self-certify with a base policy/runner: introduce it with explicit
  maintainer approval and a one-time reviewed exception to the required status, then restore enforcement.

A protected base policy is not enough if the PR may alter the engine. The supplied PR templates
extract `qa/` from the protected base SHA (`git archive`) before running CI. For external repositories,
prefer a central QA action pinned by its full commit SHA. Do not run untrusted PR code on runners
with filesystem credentials: environment scrubbing is not a sandbox.

Either way, protect `.qa/`, `qa/`, `.coderabbit.yaml` and `.github/workflows/` with CODEOWNERS (`examples/CODEOWNERS.example`).

## Promoting scanners from optional to mandatory

Start with scanners `required: false`: not installed means skipped (reported as a warning), installed means enforced. To make a
category mandatory: install a pinned, checksum-verified version in the workflow, set `"required": true` on the check, and add the category to
`required_categories`. Review that change with CODEOWNERS. The example scanner command lines are illustrative and unexecuted here: confirm the
flags and exit-code behavior of the versions you pin (for example, `govulncheck` exits 3 when it finds vulnerabilities, which is why that
profile maps `fail: [3]`).

## Branch protection checklist (GitHub)

* Require a pull request before merging, with at least one approval and **Require review from Code Owners**.
* Require status checks: **`deterministic-qa`** only. Do not require the CodeRabbit status: it is advisory.
* **Require conversation resolution before merging**: this is how CodeRabbit threads are resolved or explicitly dismissed by a human.
* Apply to administrators; disallow force pushes and branch deletion.
* Restrict who can edit workflows and dismiss reviews.

## Migrating from v0.1

1. Change `"version": 1` to `2`; add a `category` to each check; replace `block_at` with `ai_review.escalate_at`.
2. Decide `ai_review.mode`: `blocking` reproduces v0.1, `advisory` is the recommended default.
3. Replace `aqa.py run --agents none ...` with `aqa.py ci ...` and `aqa.py run --agents both` with `aqa.py review --agents both`.
4. `report.json`: `final_gate` is now `gate`; new `review`, `risk`, `policy`, `tools` sections.
