# Changelog

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
