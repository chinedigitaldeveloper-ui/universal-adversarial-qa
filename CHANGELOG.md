# Changelog

## 0.4.0 — evidence reproducibility, provenance, degradation detection & Windows support

### Added
* **Working tree provenance (`aqa-tree-v1`)**: Canonical length-prefixed working tree fingerprinting accounting for staged changes, unstaged changes, untracked non-ignored files, deletions, symlinks (without traversing outside repository scope), binary files, and special filenames (newlines, spaces).
* **Strict provenance policy**: In CI (Pipeline B), tree mutation during check execution yields `INCOMPLETE` under `provenance.enforce_tree_unchanged: true`. In local review (Pipeline A), tree mutation produces an advisory escalation.
* **Reviewer degradation detection**: Inspects reviewer stderr streams for degradation signals (rate limits, quota exhaustion, context window limits, token exhaustion, model fallback, truncated output) without false positives on harmless logs.
* **Strict reviewer enforcement**: Added `--require-reviewers` flag to `review`; exits with code 3 (`INCOMPLETE`) if any selected reviewer is missing, incomplete, or degraded.
* **Explicit finding counts**: Detailed count structures (`finding_counts`) tracking raw CLI events, raw finding events, accepted findings, deduplicated findings, open findings, suppressed findings, and breakdowns by reviewer and severity; Markdown summary renders "0 findings" when empty.
* **Human triage annotations (`.qa/triage.json`)**: CODEOWNERS-protected triage workflow metadata schema (`qa/schema/triage.json`) and loader; triage annotations attach to findings without independently changing gate outcomes or suppressing findings (`.qa/resolutions.json` remains authoritative).
* **Question-vs-defect classification**: Classifies findings as `question` vs `defect` using explicit reviewer fields or `Question:` title prefix heuristics (`kind_source: "heuristic"`); invariant enforced: question classification never downgrades severity or suppresses findings.
* **Windows platform support (P1)**: Resolved `.cmd` and `.bat` execution via `resolve_argv_windows` and `COMSPEC`; cross-platform process tree termination via `taskkill /F /T /PID` and `CREATE_NEW_PROCESS_GROUP`; case-insensitive environment scrubbing preserving Windows system essentials; path normalization.
* **Evidence integrity & artifact hashing**: Exact post-redaction SHA-256 digest of every saved artifact file recorded under `artifact_hashes` in `report.json`.
* **Derived evidence labeling**: Clear visual banners in reports and Markdown for derived/replayed evidence (`evidence_type: "derived"`) preserving original v0.3 execution records.
* **Capability probe**: Added `doctor --probe` operation to actively test reviewer CLI execution, latency, and authentication without running on every review.

### Changed
* Schema version remains `schema_version: 2` with additive, backward-compatible optional fields (`provenance`, `artifact_hashes`, `evidence_type`, `finding_counts`, `finding.kind`, `finding.triage`).
* Production policy templates in `examples/policies/*.json` updated with explicit `provenance.enforce_tree_unchanged: true`.

## 0.3.0 — pilot evidence hardening

* Fixed production PR templates to use `AQA_POLICY_SOURCE: base`; composite action defaults to `base`.
* PR workflows load `qa/` from the protected base SHA rather than trusting the PR-modified runner;
  missing trusted base engines return INCOMPLETE until an owner-reviewed bootstrap.
* Fixed CodeRabbit finding loss: bounded 8 MiB complete stdout capture, 512 KiB stderr capture;
  overflow, malformed lines, duplicate/nonterminal completion and exit/gate contradictions report INCOMPLETE.
* Negative signal exits (such as SIGKILL and SIGSEGV) classify as INCOMPLETE, while normal assertion
  failures remain FAILED.
* Pinned shared GitHub Action dependencies and per-stack setup actions by verified full SHAs;
  host-runner action compatibility has not been exercised.
* Pilot triage precision now excludes duplicates and counts `wontfix` as accepted valid risk.
* Added 11 regression tests including tampered PR runner/policy simulation.
* Live Codex and CodeRabbit CLI contracts and scanner commands remain unverified until pilot.


## 0.2.0

Architecture: two independent pipelines, with blocking evidence separated from advisory judgment.

### Added
* `aqa.py ci` (Pipeline B) and `aqa.py review` (Pipeline A). `ci` never loads AI adapters.
* Policy v2: check `category`, `required_categories`, scanner `exit_codes`, `cwd`, `env`/`env_passthrough`, `ai_review`, `risk`, `auto_fix`.
* CLI contracts (`qa/contracts/`), `contracts verify`, `smoke [--live]`, `doctor` contract checks, runtime preflight before every AI run, and
  output validation (CodeRabbit events, Codex schemas).
* Evidence report schema v2 with log hashes, fingerprints, recurrence, escalations, risk and tool data; `qa/schema/report.json`.
* Human resolutions (`.qa/resolutions.json`), expiring and CODEOWNERS-protected.
* Risk tiers and `--agents auto`.
* `--policy-source base`, policy-weakening detection, protected-file escalation.
* `pilot-report` for the five pilot metrics.
* Per-stack policies and workflows (Python, JS/TS, Go, Rust, Flutter) with SAST, dependency and secret scanner checks; scheduled CLI contract smoke workflow.
* CI annotations and step summary.

### Changed (breaking)
* AI findings are **advisory by default**: they escalate to a human instead of failing the gate. `ai_review.mode: "blocking"` restores v0.1 behavior;
  v1 policies stay blocking with a deprecation warning.
* Reports use `gate` and `review` (v0.1 `final_gate` is removed). Findings are deduplicated and carry `fingerprint`, `disposition`, `recurring`.
* Reviewers and checks diff against the **merge-base** SHA (`--base-commit`) rather than the raw base ref.
* The Codex verifier never affects the gate; it only attaches a verdict.
* `--fix` additionally requires `auto_fix.enabled` in the policy, enforces `allowed_paths` / `forbidden_paths` / `max_files`, and is refused in CI.
* Usage and internal errors exit 3 (were 2 or 1). `run` is deprecated.
* `trusted-codex-pr-review.yml` moved to `examples/optional/`; it is not part of Pipeline B.

### Security
* Repository commands run in a scrubbed environment; logs and reports are redacted.
* A timeout kills the whole process group; stdin is closed.
* Fixed during development: file names containing newlines could dodge protected-path and risk rules; untrusted text could inject CI log
  commands (`::`) through plain log lines.

### Not done / known gaps
* Real Codex and CodeRabbit binaries were not available to test against; contracts are derived from the code and the v0.1 parser.
* Scanner example command lines are unexecuted.
* Windows and macOS are not tested. Reports are unsigned.

## 0.1.0
Initial starter: single orchestrator, dual AI review with blocking severity gate, optional fix loop.
