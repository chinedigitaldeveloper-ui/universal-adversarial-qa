# Universal Adversarial QA (v0.4)

A portable, standard-library-only QA runner built on one immutable principle:

> **Deterministic evidence blocks. AI judgment advises and escalates.**

Universal Adversarial QA ships as **two independent pipelines** that share a policy file, an evidence schema, and exit-code semantics, but never share a failure mode:

```
Pipeline A: local adversarial review      optional, developer-controlled, before opening a PR
  your code (Codex or you)  ->  Codex red team  ->  CodeRabbit CLI  ->  human triage (+ optional bounded fixes)
                                  `aqa.py review`                      you review everything, then you commit

Pipeline B: PR quality gate               mandatory, deterministic, NO auto-fix, NO AI step
  pull request  ->  `aqa.py ci` (tests, types, lint, build, security)  +  CodeRabbit PR app (advisory)
                ->  branch protection + human approval  ->  merge eligible
```

| Signal | Effect on the Gate | Why |
|---|---|---|
| Failing deterministic check | **FAILED** (exit 2) | Repeatable, objective evidence |
| Required check missing, timed out, crashed, or no check covers a required category | **INCOMPLETE** (exit 3) | Unproven is not passing |
| Working tree mutated during check execution | **INCOMPLETE** (exit 3) in CI under strict policy; advisory escalation in local review | Working tree changes invalidate deterministic test credibility |
| Missing, incomplete, or degraded reviewer under `--require-reviewers` | **INCOMPLETE** (exit 3) | Fail closed when full reviewer coverage is mandatory |
| AI finding, reviewer gap, degraded reviewer, risky change, changed QA policy | *Advisory*: `human_review_required` in report, CI annotations, step summary | A variable model judgment must never become a flaky blocking status |

Repositories own **what** to run (`.qa/policy.json`). The orchestrator owns **how**: execution semantics, exit codes, process group timeouts (`_kill_tree`), environment scrubbing, secret redaction, working tree provenance (`aqa-tree-v1`), the evidence schema, and CLI tool contracts.

---

## Quick Start

1. Copy `qa/` into the repository. Copy a stack profile from `examples/policies/` to `.qa/policy.json` (`python`, `javascript-typescript`, `go`, `rust`, `flutter`).
2. Copy the matching `examples/workflows/pr-<stack>.yml` to `.github/workflows/qa.yml` and configure setup steps. Merge `examples/CODEOWNERS.example` entries so gate and triage files require owner review.
   **Bootstrap:** The first PR cannot use a base-anchored policy or runner because neither exists on the base branch yet. Merge the initial `qa/`, `.qa/policy.json`, and workflow through an explicitly owner-reviewed, one-time bootstrap process. Subsequent PRs load the QA engine **and** policy from the protected base commit by default.
3. Configure branch protection (checklist in `docs/POLICY.md`): require the `deterministic-qa` check, Code Owner review, and conversation resolution. Do **not** require the CodeRabbit status.
4. Check readiness: `python qa/aqa.py doctor --base origin/main`
5. Run the gate locally with the base policy: `python qa/aqa.py ci --base origin/main --policy-source base`
6. Optional local AI review: `python qa/aqa.py review --base origin/main`

An unconfigured repository reports **INCOMPLETE**, never a green pass: `.qa/policy.json` ships with no default checks.

---

## Commands

| Command | Purpose |
|---|---|
| `ci` | Pipeline B. Deterministic only. Never loads an AI adapter. Enforces working tree provenance. |
| `review` | Pipeline A. `--agents auto\|codex\|coderabbit\|both`, `--fix`, `--max-rounds`, `--require-reviewers`, `--strict-escalation` |
| `doctor [--probe]` | Policy validation, git base, version/flag contract check. `--probe` executes active capability test (spends tokens). |
| `contracts verify` | Probe real binaries against `qa/contracts/cli.json` (no credentials, no token cost). |
| `smoke [--live]` | Real-CLI smoke test; `--live` runs tools on a seeded canary fixture (credentials, tokens). |
| `pilot-report PATH...` | Aggregate `report.json` files and `.qa/triage.json` annotations into the five pilot metrics (`docs/PILOT.md`). |
| `run` | **Deprecated** alias for `ci` / `review`. |

Exit codes: `0` passed, `2` failed, `3` incomplete (configuration, usage, degraded reviewer with `--require-reviewers`, or internal errors), `4` only with `review --strict-escalation` when the gate passed but human review is required. Details: `docs/CONTRACTS.md`.

---

## Core Features & Architecture (v0.4)

### 1. Working Tree Provenance (`aqa-tree-v1`)
Computes an unambiguous, length-prefixed canonical fingerprint of the working tree bytes:
- Captures staged changes, unstaged modifications, untracked non-ignored files, deletions, binary files, symlinks (without following outside repository scope), and special filenames (newlines, spaces).
- **CI Gate (Pipeline B)**: Emits `INCOMPLETE` (exit 3) if the tree mutates during check execution under `provenance.enforce_tree_unchanged: true`.
- **Local Review (Pipeline A)**: Emits an advisory escalation (`tree_mutation_detected`) if mid-run tree mutation occurs.

### 2. Explicit Finding Counts & Invariants
Every review round computes an explicit count structure (`finding_counts`):
- `raw_cli_events`: Total events emitted across reviewer streams.
- `raw_finding_events`: Total candidate finding objects parsed.
- `accepted_findings`: Findings that survived contract validation.
- `deduplicated_findings`: Consolidated findings across multiple reviewers.
- `open_findings`: Deduplicated findings requiring action or review.
- `suppressed_findings`: Deduplicated findings resolved via `.qa/resolutions.json`.
- Strict count invariant: $\text{raw\_cli\_events} \ge \text{raw\_finding\_events} \ge \text{accepted\_findings} \ge \text{deduplicated\_findings} = \text{open\_findings} + \text{suppressed\_findings}$.
- Clean reviews explicitly render `0 findings (0 open, 0 suppressed)`.

### 3. Reviewer Degradation Detection
- Inspects stderr streams for rate limits, token exhaustion, quota limits, context window truncation, model fallbacks, Windows PowerShell execution policy blocks, and sandbox containment failures.
- Harmless diagnostic messages do not trigger degradation.
- Crashed or degraded verifiers record visible incomplete verification evidence and escalate.
- Adding `--require-reviewers` enforces that all selected reviewers must be healthy, exiting 3 if any are degraded or incomplete.

### 4. Human Triage Annotations (`.qa/triage.json`)
- Distinct from `.qa/resolutions.json`: Triage workflow notes (`investigating`, `confirmed`, `deferred`, `wont_fix`, `needs_info`) attach to findings as metadata (`finding["triage"]`).
- **Core Invariant**: Triage annotations **never** suppress findings or alter gate results independently. `.qa/resolutions.json` remains the sole authoritative source for accepted risks and suppressions.

### 5. Question-vs-Defect Classification
- Classifies findings as `question` vs `defect` using explicit reviewer fields or `Question:` title prefix heuristics (`kind_source: "heuristic"`).
- **Core Invariant**: Question classification never automatically downgrades severity or alters gate participation.

### 6. Windows Platform Support (P1)
- Subprocess execution: Hardened via `resolve_argv_windows` using `cmd.exe /d /s /c "..."` to protect paths and arguments containing spaces and shell metacharacters (`&`, `|`, `<`, `>`, `^`, `%`). Native `.exe` binaries are invoked directly.
- Process termination: Uses `CREATE_NEW_PROCESS_GROUP` and `taskkill /F /T /PID` to cleanly terminate full process trees on Windows.
- Environment scrubbing: Case-insensitive filtering in `scrubbed_env()` preserves Windows system essentials (`SystemRoot`, `WinDir`, `ComSpec`, `Path`, `PATHEXT`, `TEMP`, `TMP`) while scrubbing secrets case-insensitively.
- Cross-platform paths: Canonical forward-slash normalization across all git diff and provenance calculations.

### 7. Evidence Integrity & Derived Evidence
- Exact post-redaction SHA-256 hashes of all saved artifacts (`report.md`, check logs, reviewer stderr logs) are persisted under `artifact_hashes` in `report.json`.
- Replayed or converted evidence carries `evidence_type: "derived"` and renders a prominent derived-evidence banner, protecting original v0.3 execution records.

---

## What the AI Pipeline Is Allowed to Do

* `review` reads a fixed diff (merge-base with `--base`), runs independent reviewers, and writes `.qa/out/report.json` and `report.md`. Findings carry a stable `fingerprint`; a fresh read-only Codex session adds a verdict but **can never dismiss** a finding.
* Only humans suppress findings, through `.qa/resolutions.json` (CODEOWNERS-protected, expiring, with a mandatory reason).
* `--fix` is opt-in on four levels: policy `auto_fix.enabled`, `--agents both --fix`, clean tree on a feature branch, and refused in CI. After each fix, the orchestrator validates touched files against `allowed_paths`, `forbidden_paths`, `max_files`, and protected files. A violation stops the loop and marks the run INCOMPLETE; nothing is committed or auto-reverted.

---

## Layout

```
qa/aqa.py                 CLI orchestrator, gate logic, exit codes
qa/aqa_core.py            process execution, Windows resolution, aqa-tree-v1 provenance, env scrubbing, redaction
qa/aqa_policy.py          policy v2, resolutions, triage loader, risk tiers
qa/aqa_contracts.py       CLI contracts verification and event validation
qa/aqa_reviewers.py       Codex & CodeRabbit adapters, degradation detection, question classification
qa/aqa_report.py          Markdown rendering, step summaries, pilot metrics
qa/contracts/             cli.json, coderabbit-events.json
qa/schema/                report.json, resolutions.json, triage.json, codex schemas
qa/prompts/               redteam.md, verifier.md, fixer.md
qa/tests/                 158 hermetic unit/acceptance tests + live smoke
examples/                 policies (with provenance), workflows, CODEOWNERS, optional extras
docs/                     CONTRACTS.md, POLICY.md, PILOT.md
RELEASE_MANIFEST.sha256   SHA-256 manifest of all release files
```

---

## Test Verification

Run the hermetic test discovery suite:
```bash
python3 -m unittest discover -s qa/tests
```
Result: **158 total tests** (157 passed, 1 skipped live smoke test, 0 failed, 0 errors).
Verify tool contracts locally:
```bash
python3 qa/aqa.py contracts verify
```
Verify preflight configuration:
```bash
python3 qa/aqa.py doctor
```
