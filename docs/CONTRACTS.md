# Execution contracts

The orchestrator, not the repository, defines these. A repository policy chooses commands; it cannot change them.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | gate `passed` (a human may still be flagged; see the report) |
| 2 | gate `failed`: a deterministic check failed (or, in `blocking` mode, AI findings blocked) |
| 3 | gate `incomplete`: missing/unprovable evidence, **and** configuration, usage and internal errors |
| 4 | only `review --strict-escalation`: gate passed but `human_review_required` |

Usage errors exit 3, not argparse's default 2, so a typo can never be mistaken for a genuine "checks failed".
`contracts verify` and `smoke`: 2 = a tool violates its contract or the live run failed; 3 = missing/unverifiable.

## Check statuses

`passed`, `failed`, `incomplete`, `skipped` (optional tool not installed). Per check, `exit_codes`:
`{"pass": [0], "fail": [1]}`. With `fail` declared, any other exit code is `incomplete` (tool error); without it,
any non-pass code is `failed`. Exit 126/127 and negative POSIX signal exit codes are always `incomplete`. Exit 137/139 from
shell wrappers is not unambiguously a signal and must be mapped per command using `exit_codes`.

## Timeouts

Per check `timeout_seconds` (default 600, max 3600). On expiry the entire process group is `SIGKILL`ed, the check
is `incomplete`, and the run continues. AI reviewers have a 1800 s ceiling. `stdin` is always closed.

## Environment

Checks run with an **allowlisted** environment: `PATH, HOME, USER, LOGNAME, SHELL, LANG*, LC_*, TERM, TZ, TMPDIR/TEMP/TMP, CI,
selected GITHUB_* / RUNNER_*, XDG_*`, common toolchain homes (`JAVA_HOME, GOROOT, GOPATH, CARGO_HOME, RUSTUP_HOME, PUB_CACHE,
FLUTTER_ROOT, VIRTUAL_ENV, ...`). Everything else (provider keys, cloud credentials, `GITHUB_TOKEN`, `DATABASE_URL`, proxies) is
**not** inherited. Re-allow explicitly with `env_passthrough` (top level or per check); secret-like names there produce a report
warning. Static non-secret values go in `env`. Secret-like names in `env` are rejected.

## Redaction

Everything written to disk (logs, report, markdown) passes through redaction: exact values of secret-named environment variables, private
key blocks, and common token shapes (OpenAI-style, GitHub, AWS access key ids, Slack, bearer tokens, `key=value` assignments).
This is best-effort defense in depth, not a guarantee: keep secrets out of check output.

## Evidence

`<out>/report.json` (schema: `qa/schema/report.json`), `<out>/report.md`, `<out>/round-NN/check-*.log` with `log_sha256` in the report.
The report records tool and policy versions, policy sha256 and source, base / merge-base / HEAD SHAs, risk tier and reasons, per-check
status and duration, reviewer status and latency, findings (`id`, line-insensitive `fingerprint`, `disposition`, `recurring`,
verifier verdict), escalations, and fix results. In CI the same content is surfaced as annotations and the step summary.
Reports are not signed; upload them as CI artifacts for retention.

## Resolutions (`.qa/resolutions.json`, schema `qa/schema/resolutions.json`)

Human decisions on AI findings: `false_positive` or `accepted_risk`, matched by `fingerprint`, with `accepted_by`, a reason, and an
`expires` date at most 180 days out. Expired entries re-open the finding. A malformed file is a configuration error (exit 3).
Fingerprints are `reviewer|file|normalized title`, so a reworded LLM title produces a new fingerprint: this is deliberate and
conservative. CodeRabbit's native severity gate is not suppressible when it blocks without findings.

## CLI contracts (`qa/contracts/`)

`cli.json` lists, per tool: the version command and regex, an optional `min` version (enforced), and help probes whose
`must_contain` flags are exactly those `aqa_reviewers.py` passes (a test fails if code and contract diverge). Flag matching is
word-boundary exact, so `--base` does not satisfy `--base-commit`.
`coderabbit-events.json` is the output contract for `coderabbit review --agent`: only fields the gate depends on are required;
unknown event types are ignored; a missing `complete` event, an unknown severity or a missing gate result makes the review
`incomplete` instead of clean. v0.3 also rejects any non-JSON stream line, output over 8 MiB stdout / 512 KiB stderr,
more than one `complete`, a nonterminal `complete`, or a contradictory exit status (`0` with blocked gate,
`2` with passed gate). Capture overflow kills the review process group; partial evidence is never a clean review.
These strict output assumptions must be confirmed against **real installed CLI versions** in the pilot. Codex output is validated against `qa/schema/codex-*.json`.

| Check | Command | Needs credentials | Spends tokens |
|---|---|---|---|
| presence, version floor, flags | `contracts verify` / `doctor` | no | no |
| same, plus a report file | `smoke` | no | no |
| real invocation on a seeded fixture, output validated | `smoke --live` | yes | yes |

To change a contract: edit `cli.json` in a reviewed commit. Set Codex's `min` after the pilot has established a tested version.
`smoke --live` records whether the seeded SQL-injection canary was flagged; this is **informational only**, because LLM recall is not a
pass/fail criterion.

## Risk tiers

Computed from changed paths and size (defaults in `aqa_policy.py`, overridable by `risk.rules`). `high`: workflows, QA/CODEOWNERS,
auth/crypto/security/payment/billing, migrations, container/IaC, env files, or large changes. `medium`: dependency manifests,
lockfiles, or 40+ changed lines. `low`: docs and small changes. `--agents auto` maps tier to reviewers (default
`low: none`, `medium: coderabbit`, `high: both`). A `high` tier is always escalated to a human. The risk heuristic is path-based
and will miss a dangerous one-line change in an ordinary file; pass `--agents` explicitly when in doubt.
