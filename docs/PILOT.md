# Pilot plan: one representative repository

Goal: decide with data whether to roll the starter out, and whether to enable anything beyond deterministic CI.
**Set the thresholds below before the pilot starts**; the numbers here are starting hypotheses, not findings.

## Setup (day 1)

1. Pick one repository with real tests, a CI history and 3 to 10 active contributors.
2. Adopt the stack policy and workflow, branch protection, CODEOWNERS (see `README.md`, `docs/POLICY.md`).
3. Install the AI CLIs at pinned versions. Run `python qa/aqa.py contracts verify`, then `python qa/aqa.py smoke --live`.
4. Make a baseline: how long does current CI take, how many PRs per week, what are the current escape and review-noise numbers.

## Canary PRs (week 1)

Open at least 10 PRs with **known** outcomes, each a distinct commit (the expected-labels file keys on HEAD SHA):

* 4 clean (expect `passed`), 2 with a failing test (`failed`), 1 with a lint error (`failed`), 1 with a planted secret (`failed`
  if the scanner is installed and mandatory),
* 2 that must be `incomplete`: a required tool missing from the runner, and a check that exceeds its timeout.
* Re-run every canary once: the verdict on the same SHA must not change.

Plant 3 to 5 realistic defects (authz gap, SQL built by string concatenation, race, missing failure-path test) in separate changes
for Pipeline A, to see what each reviewer finds.

## Live use (weeks 2 to 3)

Developers run `aqa.py review` before opening PRs. Collect each PR's evidence: `report.json` from CI (upload artifacts) and from local
runs. Triage every escalated finding into `triage.json`: `{"<fingerprint>": "actionable|false_positive|duplicate|wontfix"}`.

## Measure

```
python qa/aqa.py pilot-report evidence/ --expected expected.json --triage triage.json
```
`expected.json`: `{"<head sha prefix>": "passed|failed|incomplete"}` for the canaries.

| # | Metric | Source | Starting threshold (edit before you begin) |
|---|---|---|---|
| 1 | Real CLI compatibility | `contracts verify`, `smoke --live`, `tools` + `contract_violations` in reports | every pilot machine and CI image `ok`; zero runtime contract violations; live smoke passes |
| 2 | Review usefulness | triage labels: precision = (actionable + wontfix) / (actionable + wontfix + false_positive), excluding duplicate, per reviewer; reviewer completion rate | agree a minimum precision and a maximum false escalations per PR; reviewers complete on >= 95% of runs |
| 3 | CI reliability | classification accuracy on canaries; same-SHA rerun stability; top `incomplete` reasons | 100% of canaries classified as expected; zero verdict flips |
| 4 | Latency and cost | run p50/p95, slowest checks, reviewer latency; **cost from provider billing** (the tool records wall-clock only) | deterministic gate p95 within an agreed budget; AI cost per reviewed PR within an agreed budget |
| 5 | Fix safety | `fix_safety` (attempts, scope violations); human diff review of every fix | zero scope violations; every fixer change reviewed before commit |

## Decisions after the pilot

* **Roll out Pipeline B** if metrics 3 and 4 pass. It is useful with no AI at all.
* **Recommend Pipeline A** to developers if metrics 1 and 2 pass; set Codex's `min` version in `qa/contracts/cli.json` from what you tested.
* **Enable `auto_fix`** (P2) only if 2 and 5 pass, for specific path scopes, on feature branches, never in CI.
* **Do not** add more agents or autonomous PR fixes (P3) without measured benefit from this data.
* Consider `ai_review.mode: "blocking"` only for a repository whose measured precision justifies it.

## Known limits to keep in mind

* `smoke --live` uses a tiny fixture; passing it proves format compatibility, not review quality.
* Latency and token cost depend on your diffs; the seeded fixture is not representative.
* The risk tiers are path-and-size heuristics.

### Metric normalization (v0.3)

Duplicate findings are **excluded** from the actionable-precision denominator (but counted in
`duplicates_excluded`). `wontfix` means the issue is valid but accepted/declined, so it counts as a
true positive and appears as `accepted_risk`. A finding with only `duplicate` labels has `precision: null`
(not a misleading 0 or 1). Freeze the labels and the `>=70%` proposal before the first pilot run.

A v0.3 canary must additionally demonstrate that changes to `qa/aqa.py` and `.qa/policy.json` on a
PR do not change the gate result: the template's `git archive` loads the protected base revision.
The first bootstrap PR is a manual exception, not a passing CI gate.
