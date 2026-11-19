# Universal Adversarial QA (v0.3)

A portable, standard-library-only QA runner built on one rule:

> **Deterministic evidence blocks. AI judgment advises and escalates.**

It ships as **two independent pipelines** that share a policy file, an evidence schema and exit-code
semantics, but never share a failure mode.

```
Pipeline A: local adversarial review      optional, developer-controlled, before opening a PR
  your code (Codex or you)  ->  Codex red team  ->  CodeRabbit CLI  ->  human triage (+ optional bounded fixes)
                                  `aqa.py review`                      you review everything, then you commit

Pipeline B: PR quality gate               mandatory, deterministic, NO auto-fix, NO AI step
  pull request  ->  `aqa.py ci` (tests, types, lint, build, security)  +  CodeRabbit PR app (advisory)
                ->  branch protection + human approval  ->  merge eligible
```

| Signal | Effect on the gate | Why |
|---|---|---|
| Failing deterministic check | **FAILED** (exit 2) | repeatable evidence |
| Required check missing, timed out, crashed, or no check covers a required category | **INCOMPLETE** (exit 3) | unproven is not passing |
| AI finding, reviewer gap, risky change, changed QA policy | *advisory*: `human_review_required` in the report, CI annotations, step summary | a variable model judgment must not become a flaky required status |

Repositories own **what** to run (`.qa/policy.json`). The orchestrator owns **how**: execution semantics,
exit codes, timeouts (whole process group is killed), environment scrubbing, secret redaction, the evidence
schema and the CLI contracts.

## Quick start

1. Copy `qa/` into the repository. Copy a stack profile from `examples/policies/` to `.qa/policy.json`
   (`python`, `javascript-typescript`, `go`, `rust`, `flutter`).
2. Copy the matching `examples/workflows/pr-<stack>.yml` to `.github/workflows/qa.yml` and fill in the setup steps.
   Merge `examples/CODEOWNERS.example` entries so the gate files need owner review.
   **Bootstrap:** the first PR cannot use a base-anchored policy or runner because neither exists yet on
   the base branch. Merge the initial `qa/`, `.qa/policy.json`, and workflow only through an explicitly
   owner-reviewed, one-time bootstrap process (do not make an unchecked green PR gate). Subsequent
   PRs use the protected base commit's QA engine **and** policy by default.
3. Configure branch protection (checklist in `docs/POLICY.md`): require the `deterministic-qa` check,
   Code Owner review, and conversation resolution. Do **not** require the CodeRabbit status.
   CI templates execute the QA engine extracted from the protected base commit. For multi-repo deployments,
   prefer the centrally hosted composite action pinned to a reviewed full SHA.
4. Check readiness: `python qa/aqa.py doctor --base origin/main`
5. Run the gate locally with the same **base policy** as CI (after bootstrap): `python qa/aqa.py ci --base origin/main --policy-source base`
6. Optional local AI review: `python qa/aqa.py review --base origin/main`

An unconfigured repository reports **INCOMPLETE**, never a green pass: `.qa/policy.json` ships with no checks.

## Commands

| Command | Purpose |
|---|---|
| `ci` | Pipeline B. Deterministic only. Never loads an AI adapter. |
| `review` | Pipeline A. `--agents auto\|codex\|coderabbit\|both` (auto picks by change risk), `--fix`, `--max-rounds`, `--strict-escalation` |
| `doctor` | Policy validation, git base, version/flag check of the real AI CLIs |
| `contracts verify` | Probe the real binaries against `qa/contracts/cli.json` (no credentials, no cost) |
| `smoke [--live]` | Real-CLI smoke test; `--live` runs the tools on a seeded fixture (credentials, tokens) |
| `pilot-report PATH...` | Aggregate `report.json` files into the five pilot metrics (`docs/PILOT.md`) |
| `run` | **Deprecated** alias for `ci` / `review` |

Exit codes: `0` passed, `2` failed, `3` incomplete (also configuration, usage and internal errors),
`4` only with `review --strict-escalation` when the gate passed but a human must look.
Details: `docs/CONTRACTS.md`.

## What the AI pipeline is allowed to do

* `review` reads a fixed diff (merge-base with `--base`), runs independent reviewers, and writes
  `.qa/out/report.json` and `report.md`. Findings carry a stable `fingerprint`; a fresh read-only Codex session
  adds a verdict but **can never dismiss** a finding.
* Only humans suppress findings, through `.qa/resolutions.json` (CODEOWNERS-protected, expiring, with a reason).
* `--fix` is opt-in on four levels: the policy must set `auto_fix.enabled`, you must pass `--agents both --fix`,
  the tree must be clean on a feature branch, and it is refused in CI. After each fix the orchestrator checks
  which files changed against `allowed_paths`, `forbidden_paths`, `max_files` and the protected QA/CI files.
  A violation stops the loop and marks the run INCOMPLETE; nothing is auto-reverted and nothing is committed.

## Layout

```
qa/aqa.py                 CLI and the two pipelines
qa/aqa_core.py            process runner, env scrubbing, redaction, git helpers, schema validator
qa/aqa_policy.py          policy v2, resolutions, risk tiers
qa/aqa_contracts.py       CLI contract verification and output validation
qa/aqa_reviewers.py       Codex / CodeRabbit adapters (Pipeline A only)
qa/aqa_report.py          Markdown, CI annotations, pilot metrics
qa/contracts/             CLI contract + CodeRabbit event contract
qa/schema/                report, resolutions, Codex output schemas
qa/prompts/               red-team, verifier, fixer prompts
qa/tests/                 hermetic tests (fake CLIs) + conditional real-CLI tests
examples/                 stack policies, per-stack workflows, CODEOWNERS, optional extras
docs/                     CONTRACTS.md, POLICY.md, PILOT.md
```

## Honest status

v0.2 was tested on Linux/Python 3.12 (89 passing, 3 conditional skips).
In v0.3 the additional regression tests cover complete bounded CodeRabbit streams, malformed NDJSON,
process signal crashes, and a malicious PR modifying both the policy and checked-out runner.
Run `python -m unittest discover -s qa/tests` to verify the version you installed.

**Not verified here:** the real Codex and CodeRabbit binaries (not installed; no network), live model
behavior, GitHub Actions runners, macOS/Windows, and the scanner command lines in `examples/policies/`
(gitleaks, semgrep, bandit, ...; check flags against the versions you pin). The CLI contract is derived from
the invocations in `qa/aqa_reviewers.py` and the event fields the v0.1 parser already used; the first pilot run
(`contracts verify`, then `smoke --live`) is what proves it against reality. See `docs/PILOT.md`.

## v0.3 hardening notes

* Production PR templates now load **both policy and runner from the protected base commit**. They fail
  with exit `3` when no trusted runner exists yet. The central action defaults `policy-source: base`.
* CodeRabbit uses a complete-or-incomplete bounded capture (8 MiB stdout / 512 KiB stderr). Malformed
  NDJSON, truncated output, duplicate/nonterminal completion and exit/gate contradictions mark review
  `incomplete`; no missing findings are silently treated as zero.
* POSIX signal-terminated checks are `incomplete`, not normal assertion failures.
* Pilot precision excludes `duplicate`; `wontfix` is treated as an accepted valid finding; the report
  exposes the denominator explicitly. Freeze those rules before piloting.
* The workflow examples pin included third-party setup/upload actions by full SHA as a starting point.
  Older action runtimes may need upgrading and re-pinning for your GitHub runners. **Do not assume
  these examples have been executed on GitHub Actions**, and validate scanner commands separately.
* Local CLI defaults remain `--policy-source worktree` for developer convenience. Production workflows
  explicitly use `base`. First-merge bootstrap requires a deliberate human-controlled exception.
