# Architecture (v0.2): two independent pipelines

## Principle

Separate **blocking evidence** from **advisory judgment**.

* Deterministic evidence is repeatable. A failure blocks; a missing mandatory check is `INCOMPLETE`, never green.
* An LLM finding is a variable judgment. It is recorded, verified where possible, and **escalated to a human**.
  It does not become a failing required status unless a repository explicitly opts in (`ai_review.mode: "blocking"`).

That keeps the fail-closed property (unproven is not passing) without letting review noise paralyze delivery.

## Pipeline A: local adversarial review (optional, developer-controlled)

```
 implementation (you or Codex; outside the orchestrator)
        |
        v
 Codex red team (read-only, independent session) ----+
                                                      +--> findings --> fresh Codex verifier (read-only, evidence only)
 CodeRabbit CLI (independent engine)  ---------------+                         |
        |                                                                       v
        +--> deterministic checks (same as CI) ------------------> report.json / report.md
                                                                               |
                                              human triage  <------------------+
                                      (+ optional bounded Codex fix loop, off by default)
                                              |
                                       you review the diff, then YOU commit
```

Command: `python qa/aqa.py review`. Reviewer selection can follow change risk (`--agents auto`).
Nothing is committed, pushed or merged by the tool.

## Pipeline B: PR quality gate (mandatory, deterministic, no auto-fix)

```
 pull request opened / updated
        |
        +--> deterministic CI: `aqa.py ci`  (tests, types, lint, build, security scanners)   <-- required status
        |
        +--> CodeRabbit PR app                                                              <-- advisory findings
        |
        v
 branch protection: `deterministic-qa` must pass + Code Owner approval + conversations resolved
        |
        v
 merge eligible
```

Pipeline B contains no AI step, no API key and no auto-fix; `aqa.py ci` never imports the AI adapters
(asserted by a test). The two pipelines share only the policy file, report schema and exit codes.

## Gate semantics

| Input | Status | Notes |
|---|---|---|
| any required check failed | `failed` (2) | scanners may declare `exit_codes.fail`; any other exit code is a tool error, not a verdict |
| required check missing / timed out / crashed | `incomplete` (3) | process group killed on timeout |
| `required_categories` has no covering required check | `incomplete` (3) | e.g. policy demands `test`, none configured |
| optional check not installed | `skipped` + report warning | visible, never silent |
| AI finding >= `escalate_at` (default `major`) | gate unchanged; **escalation** | human triage |
| requested reviewer missing / contract violated / malformed output | gate unchanged; **review_gap escalation**, `coverage: partial` | in `blocking` mode: `incomplete` |
| changed QA/CI/ownership files, weakened policy, high-risk paths | gate unchanged; **escalation** | CODEOWNERS review |

Precedence: `failed` > `incomplete` > `passed`.

## Trust boundaries

| Concern | Control |
|---|---|
| PR changes the gate that judges it | `--policy-source base` evaluates the merged base policy; changed/weakened policy is always escalated; CODEOWNERS on `.qa/`, `qa/`, workflows |
| Repo commands see secrets | checks run with an allowlisted environment; secret-like names are never inherited unless named in `env_passthrough`; logs and reports are redacted |
| Hung or runaway commands | per-check timeout kills the **whole process group**; stdin is closed |
| CLI drift breaks review silently | version floor + flag probes against the real binary, runtime output validation, preflight before every AI run |
| Malicious file names / titles injecting CI log commands | all untrusted text is sanitized before it is printed or written to the step summary; glob rules are newline-safe |
| Fixer edits outside its remit | policy-enabled, bounded, path-scoped; protected files always off limits; violation stops the loop |
| AI instructions inside the repo | prompts treat repository content as untrusted; verifier cannot dismiss findings; only humans resolve (`.qa/resolutions.json`) |

## Roadmap status

| Priority | Item | Status in v0.2 |
|---|---|---|
| P0 | Real CI checks per stack | stack policies + workflows for Python, JS/TS, Go, Rust, Flutter (commands not executed against real projects here) |
| P0 | Actual CLI smoke tests | `contracts verify` and `smoke [--live]` are implemented and tested against fakes; **not yet run against the real tools** |
| P0 | Version and output contracts | implemented (`qa/contracts/`); Codex has no version floor until the pilot establishes one |
| P1 | SAST, dependency, secret scanning | categories, exit-code mapping and example scanner checks; scanners are optional until installed |
| P1 | Structured review evidence | `report.json` schema v2, log hashes, fingerprints, resolutions |
| P1 | Risk-based review selection | tiers from paths and size; `--agents auto` |
| P2 | Optional bounded auto-fix | implemented, off by default; enable only after the pilot shows acceptable accuracy |
| P3 | More agents, autonomous PR fixes | deliberately **not** built; needs measured benefit |

The next milestone is the pilot in `docs/PILOT.md`, not more features.

## v0.3 trust-boundary refinement

Production PR templates run the QA orchestration **from the protected base revision** (the PR can
change application files but cannot change the gate's runner or policy for that run). Centralized
composite actions must be pinned to a reviewed commit. The first adoption requires a manually reviewed
bootstrap since the base does not yet contain policy and engine. Untrusted check code still runs in the
CI job: use ephemeral minimally privileged runners, no credentials and branch protections.

CodeRabbit receives a complete-or-incomplete bounded stream; malformed, oversized, nonterminal and
contradictory evidence escalates to a human and can never masquerade as an empty successful review.
