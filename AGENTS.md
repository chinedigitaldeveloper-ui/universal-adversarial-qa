# Universal Adversarial QA Repository Instructions

## Project Structure & Module Organization

- `qa/`: Core orchestrator and execution engine.
  - `qa/aqa.py`: Main CLI entrypoint (`ci`, `review`, `doctor`, `contracts`, `smoke`, `pilot-report`).
  - `qa/aqa_core.py`: Subprocess execution, process-group timeout supervision (`_kill_tree`), environment scrubbing, secret redaction, and working tree provenance (`aqa-tree-v1`).
  - `qa/aqa_policy.py`: Policy loading, JSON schema validation, base commit resolution, resolutions (`.qa/resolutions.json`), and triage annotations (`.qa/triage.json`).
  - `qa/aqa_reviewers.py`: Adversarial AI reviewer adapters (Codex red team, CodeRabbit CLI), degradation detection patterns, and question-vs-defect classification.
  - `qa/aqa_report.py`: Markdown and JSON report generation, explicit finding count rendering, post-redaction artifact hashing, and derived evidence notice banners.
  - `qa/contracts/`: Version-pinned CLI contracts (`cli.json`).
  - `qa/schema/`: Canonical JSON schemas (`report.json`, `policy.json`, `triage.json`).
  - `qa/prompts/`: System and user prompt templates for adversarial AI review rounds.
  - `qa/tests/`: Comprehensive unit and integration test suite (134 tests).
- `docs/`: Architecture specifications, policy guides, CLI contracts, threat models, and pilot protocols (`CONTRACTS.md`, `POLICY.md`, `PILOT.md`, `ROADMAP.md`).
- `examples/`: Reference policies for Python, JavaScript/TypeScript, Go, Rust, Flutter, and GitHub Actions workflow templates.
- `.qa/`: Local repository policy configuration (`policy.json`, `resolutions.json`, `triage.json`).

The parent workspace organizes `evidence/` for immutable historical evidence, `version/` for version archives, and `worktree/` for additional Git worktrees. Consult the parent `AGENTS.md` for workspace-level guidance.

---

## Commands

Run commands from this directory (or the active worktree):

- **Run all automated tests**:
  ```bash
  python3 -m unittest discover -s qa/tests
  ```
- **Verify CLI contracts** (no credentials or tokens required):
  ```bash
  python3 qa/aqa.py contracts verify
  ```
- **Inspect environment and doctor check**:
  ```bash
  python3 qa/aqa.py doctor --base origin/main
  ```
  *(Add `--probe` to execute an active capability probe spending tokens)*
- **Run Pipeline B (Deterministic CI Gate)**:
  ```bash
  python3 qa/aqa.py ci --base origin/main
  ```
- **Run Pipeline A (Adversarial AI Review)**:
  ```bash
  python3 qa/aqa.py review --base origin/main
  ```
  *(Use `--require-reviewers` to enforce exit code 3 if any reviewer is degraded, missing, or incomplete)*
- **Run smoke tests**:
  ```bash
  python3 qa/aqa.py smoke
  ```
  *(Use `--live` with `AQA_LIVE_SMOKE=1` to run live external tool verification)*

---

## Core Invariants & Safety Principles

1. **Pipeline Independence**:
   - Pipeline B (deterministic CI) never executes AI steps, never consumes AI credentials, and never performs automated fixes.
   - Deterministic test failures block the gate (exit 2). AI findings remain advisory (exit 0 with warnings, or exit 4 only under `--strict-escalation`).
2. **Canonical Provenance (`aqa-tree-v1`)**:
   - Working tree fingerprints use length-prefixed encoding covering staged, unstaged, untracked, deleted, binary, and symlinked files.
   - If the working tree mutates during Pipeline B check execution under strict policy, the runner exits `INCOMPLETE` (exit 3).
3. **Reviewer Degradation Detection**:
   - Reviewer stderr streams are inspected for rate limits, token exhaustion, quota denials, context window truncation, model fallbacks, Windows PowerShell execution policy blocks, and sandbox containment failures.
   - Harmless warnings must not trigger degradation.
   - When `--require-reviewers` is specified, degraded or incomplete reviewers trigger exit code 3.
4. **Human Triage Invariant**:
   - `.qa/triage.json` records human triage annotations (`investigating`, `confirmed`, `deferred`, `wont_fix`, `needs_info`).
   - Triage annotations **never** suppress findings or alter gate results independently. `.qa/resolutions.json` remains the sole authoritative source for accepted suppressions.
5. **Question Classification Invariant**:
   - Classifying findings as `question` vs `defect` is purely informational and must **never** downgrade finding severity or gate behavior.
6. **Windows Security Hardening**:
   - Windows command execution directly executes native executables and unwraps verified `.cmd`/`.bat` shims (`unwrap_cmd_shim`) directly into target runtimes (Node.js, Python, or binaries) without invoking `cmd.exe`. Unsupported, complex, or ambiguous shims fail closed (`UnsupportedShimError`, exit code 126 in subprocess runners) to prevent command injection and argument corruption from shell metacharacters (`&`, `|`, `<`, `>`, `^`, `%`).
   - Process tree termination on Windows uses `CREATE_NEW_PROCESS_GROUP` and `taskkill /F /T /PID`.
7. **Evidence Integrity**:
   - Artifact hashes in reports are computed strictly *after* secret scrubbing.
   - Derived evidence is explicitly flagged with `evidence_type: "derived"`.

---

## Code Style & Testing Standards

- **Standard Library Only**: No external pip dependencies. Rely strictly on Python standard library modules.
- **Cross-Platform Primitives**: Write path operations that normalize to forward slashes. Ensure process supervision handles both POSIX process groups (`os.killpg`) and Windows process trees (`taskkill`).
- **Test Invariants**: Maintain all 149 automated unit and integration tests (148 passing, 1 skipped canary test reserved for live smoke environments with `AQA_LIVE_SMOKE=1`) in `qa/tests/`. Ensure count invariants hold across all review and report scenarios:
  $$\text{raw\_cli\_events} \ge \text{raw\_finding\_events} \ge \text{accepted\_findings} \ge \text{deduplicated\_findings} = \text{open\_findings} + \text{suppressed\_findings}$$
- **Schema Compatibility**: Preserve `schema_version: 2` with additive, optional fields.

---

## Git & Change Safety

- **Development Branch**: Active local development and all feature merges must target `dev` (never `main`).
- **Protected `main` Branch**: `main` is strictly reserved for stable, authorized release snapshots (e.g. `v0.3.0`, `v0.4.0`). Never commit or merge directly into `main`. Promotion from `dev` to `main` requires explicit release approval.
- **Worktree-First Development**: Always start new work in a dedicated worktree under `../worktree/` (e.g., `worktree/<task-name>`). Direct commits to `dev` are strictly reserved for trivial edits (e.g., a couple of lines of documentation or quick fixes). All substantive changes must be developed and verified in worktrees before merging into `dev`.
- **Pre-commit Checks**: Review `git status -sb` and `git diff --check` before committing.
- **Commit Messages**: Use imperative commit subjects (e.g., `feat: ...`, `fix: ...`, `docs: ...`).
- **Evidence Immutability**: Historical v0.3 receipts and PR #35 evidence under `../evidence/pr-35/original-v0.3/` are strictly immutable.
