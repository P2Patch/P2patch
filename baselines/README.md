# `baselines/` — running other papers' tools against our dataset

Third-party repair tools we compare against, and the harness that runs them on our cases.

**The rule this directory exists to enforce: their code never enters our history; only normalized
results come back.** The clones are nested git repos (the same reason `security_pipeline_runs/`
is ignored), they carry their own licenses — one carries none at all — and they are large. So
`vendor/` and `work/` are gitignored, and the only committed outputs are `results/`, `cases.json`,
and the transcribed `paper_reported/` tables.

See `../BASELINE_COMPARISON.md` for what each baseline does, what it claims, and the comparison
protocol these artifacts feed.

## Layout

```
baselines/
  pins.json               committed  repo URL + commit for each baseline. Pin everything.
  setup.sh                committed  clones/checkouts every pin into vendor/
  cases.json              generated  the join: our dataset <-> each baseline's benchmark
  schema/                 committed  the one result shape every baseline normalizes into
  paper_reported/         committed  per-case results transcribed from the papers (zero-compute comparison)
  common/                 committed  shared harness code (case map, normalizers, scorers)
  <baseline>/             committed  OUR adapter + run script + notes for that tool
  results/                committed  normalized results — the only run output that ships
  vendor/                 IGNORED    the clones themselves
  work/                   IGNORED    scratch: containers, raw logs, intermediate output
```

## Getting started

```bash
./setup.sh                       # clone every baseline at its pinned commit into vendor/
./setup.sh san2patch-benchmark   # just one
VERIFY=1 ./setup.sh              # report drift without touching anything

python3 common/build_case_map.py # regenerate cases.json (do this after setup.sh — it prefers
                                 # the cloned VulnLoc metadata over the checked-in fallback)
```

## Why the dataset overlap is unusually good

`cases.json` computes it, and the answer is: **all 43 of our C/C++ cases are in LoopRepair's
VulnLoc+**, 37 are in the VulnLoc benchmark San2Patch ships, and 19 are in PatchAgent's published
per-case table. Our C/C++ subset and these papers' benchmark are effectively the same benchmark.

Two consequences:

1. **Published per-case numbers exist for most of our C/C++ cases before we run anything.**
   That is `paper_reported/`. It is a weaker form of evidence than running the tools (different
   harnesses, different functional tests, different model eras) — never pool it with `results/`.
2. **`vendor/san2patch-benchmark` fills our single biggest gap.** All 43 of our C/C++ cases
   currently have `test_command = true` — a literal no-op, so our regression gate is vacuous on
   C/C++ and any "functional tests pass" claim would be free. That benchmark ships, per case,
   `config_func.sh` / `build_func.sh` / `test_func.sh`: a *separate non-sanitizer build* plus a
   `make check` runner with per-project tolerance for pre-existing failures. Those are what our
   C/C++ `test_command` should become — used identically by us and by every baseline, or the
   comparison measures harness differences instead of repair quality.

Their 7 cases with no usable functional test at all (`gnubug-19784`, `CVE-2016-8691`,
`CVE-2016-9557`, `CVE-2016-5844`, `CVE-2017-5974/5975/5976`) must be excluded from every
functional-gate denominator on **both** sides, not silently scored as passes.

## Adding a baseline

1. Add it to `pins.json` (URL, commit, license, and what the paper's numbers belong to if the
   repo has since diverged — PatchAgent's has).
2. `./setup.sh <key>`.
3. Create `baselines/<key>/` with an adapter that drives the tool over `cases.json` and a
   `notes.md` recording anything surprising about running it.
4. Normalize output to `schema/baseline_result.schema.json` and write it under
   `results/<key>/<batch>/`.
5. **Before trusting any number: reproduce 2–3 cases the paper reports, and check you get their
   answer.** If you can't reproduce their own cases, the adapter is wrong, not the tool.

## Same CVE ≠ same commit

`cases.json` joins on `cve_id`, which establishes the two benchmarks mean the same
*vulnerability*. It does not establish they check out the same *revision*, and for three
cases they do not — `python3 common/build_case_map.py` reports the count, and
`baseline_base` carries the per-case verdict.

The interesting ones are zziplib. Upstream fixed CVE-2017-5974 and CVE-2017-5975 **twice
each**, and VulnLoc pins the bug at the first, incomplete fix (`03de3be`, `33d6e9c`)
where VulnLoc+ pins it before any fix (`3a4ffcdd`). A San2Patch patch for those cases is
a diff against code that only exists after the newer commit: one was rejected by
`git apply`, the other applied by context and then failed to compile (`use of undeclared
label 'error'`). Both showed up as an errored replay, which is honest but is not a score.

So `score_patches.py` reads each case's base from the benchmark's own `setup.sh` and,
when it differs, scores the patch on **its** commit via `replay-patch --base-revision`.
That is only sound because of the guard attached to it: every POV is first re-run on the
**unpatched** tree at that commit, and one that no longer reproduces there is recorded
inconclusive instead of counted as blocked. Without it, a benchmark that happened to pin
a commit *after* the relevant fix would hand its tool a free 1.00.

Two deliberate non-behaviours: the shared `dataset/project-sources` clone is never
fetched into (a private clone under the replay dir supplies the commit — that checkout is
read by our own runs and by every other baseline, and it is not this harness's to
deepen), and a benchmark ref that cannot be resolved offline reports `unresolved` and
keeps the old behaviour rather than guessing. Settle those with
`git ls-remote <url> 'refs/tags/<tag>^{}'` and add the result to
`patch_source.KNOWN_TAG_COMMITS`.

## The oracle moves; the scores do not

These POV sets are actively authored, and `score_patches.py` skips what is already
scored — so a manifest that gains a POV leaves a stale number behind forever. Every
skipped row is now compared against the current manifest and reports `oracle_drift`;
`--recheck-stale` re-scores exactly those. A number computed against a POV set that has
since changed is not wrong so much as *about something else*, and the report says so.

## Rules

- **Pin every clone.** A baseline whose commit moves under us is not a baseline.
- **Score a patch on the commit it was written for.** And prove the vulnerability is
  actually present on that commit before believing any number that comes out.
- **Never vendor their code.** `looprepair` in particular ships without a license file — running
  it in place from `vendor/` is fine, copying it into our tree is not.
- **Record the model.** Every one of these papers was evaluated on 2024/2025-era models. A gap
  against a current model is a finding about model era unless you control for it.
- **Record the budget.** PatchAgent runs 15 iterations, LoopRepair 3 × 5 candidates, ours 1 run
  with ≤3 correction attempts. Un-matched budgets are the easiest way to publish a wrong number.
- **`errored` is not `failed`.** Infrastructure failures come out of the denominator; they are
  not losses for the tool. Same split our own pipeline makes between `errored` and `rejected`.
- **Keep secrets out.** The baselines read their own `.env` for API keys; those paths are
  gitignored here. Do not put a key in `pins.json` or any adapter.
