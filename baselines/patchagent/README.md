# `baselines/patchagent/` — PatchAgent, and how its results got here

PatchAgent (USENIX Security '25) is pinned in `../pins.json`. Unlike San2Patch, **it was not
driven by an adapter in this directory.** It ran out of band, inside its own artifact
container (`patchagent-artifact`), and its patches were scored against our POV sets by a
separate build-and-replay driver. What is committed here is the *conversion* of that native
output into the shapes this repo already reads:

```
normalize_run.py     the one-way conversion. Re-runs nothing, re-scores nothing.
                     Writes ../results/patchagent/<arm>/ and nothing else.
```

Regenerate (the source archives live outside the repo by design — see `../README.md`'s
"Never vendor their code"):

```bash
python3 baselines/patchagent/normalize_run.py \
    --run-dir    /path/to/haiku-4.5-15cases \
    --pov-scores /path/to/povscore15/results.json \
    --arm skyset-haiku45
```

The script fails loudly rather than guessing: if a POV-score row's commit or project slug
disagrees with `../cases.json`, it exits instead of preferring one side.

## Three things about this arm that a number alone would hide

**1. The iteration cap is not uniform.** 14 cases ran at `--max-iteration 3`; coreutils
`ca99c52` (our `gnubug-25023`) ran at **15**, because it fails at 3. Those are two
experiments, so they are two batches — `b1-haiku45-iter3` and `b2-haiku45-iter15` — and every
row also carries its own `max_iteration` plus an `effort_comparable` flag. "15/15 at one
setting" is not a statement this data supports and is not producible from it.

**2. Costs are measured token counts.** `langchain_openai` reports no usage on this path, so
every call was re-counted through Anthropic's `count_tokens` endpoint, including the three tool
schemas shipped with — and billed on — every request. That gives **$4.79** across the arm,
de-duplicated on the underlying run so a single patch covering two CVEs is counted once.
`cost_basis` is `measured_tokens` on every row and batch. The raw traces are committed under
each case's `traces/`, so the counts can be re-derived rather than taken on trust. Note the
recorder captured what `ChatOpenAI` callbacks reported; retried or internally-issued calls may
not appear. The user-reported total for all experiments with this system across the whole
project is **$25.03**.

**3. One PatchAgent case is not always one of our cases.** PatchAgent keys by
`<project>-<commit>-<bug_type>`; everything here joins on `case_id` (= our `cve_id`), per
`../cases.json`. `extractfix-libtiff-c421b99-heap_buffer_overflow` is **one run whose single
patch covers CVE-2016-3186 and CVE-2016-5314**, and our POV sets score it separately under
each — and *disagree*: 0/2 blocked as CVE-2016-3186, 2/2 as CVE-2016-5314. Rows are therefore
per `case_id`, because that is the only key the POV scores exist at, and the two rows that
share one run declare it in `shared_run_with`. Every cost and effort total de-duplicates on
`patchagent_case`, so one run's spend is never counted twice. (San2Patch's own benchmark
*excludes* both of these cases as unreproducible under sanitizer instrumentation, so there is
no San2Patch column to compare them against.)

## The case that is absent

`extractfix-coreutils/658529a-heap_buffer_overflow` (our `gnubug-19784`) — 16 shared skyset
cases, 15 ran. Its `test.sh` hardcodes `grep "FAIL:  4"` for that commit while the
**unpatched** baseline on this machine yields `FAIL: 3`, so PatchAgent's `validate()` would
reject every candidate regardless of correctness. It reproduces fine; only the functional gate
is unusable. It is recorded `outcome: inapplicable` with a reason — an environment result, not
a repair failure — and is excluded from every denominator rather than scored zero, per
`schema/baseline_result.schema.json` ("Applicability is a result, not a gap in the data").

## POV re-scoring, and the two directions it runs in

`pov_scores_fixpov.json` / `pov_scores_respov.json` roll up the per-case
`<batch>/gen_patch/<case_id>/{fix_pov,residual}/results.json` (recorded batches predating the rename use `ground_truth/`), written in exactly the
shape `dashboard/backend/runs.py` already reads, so the dashboard renders these through the
same panels a pipeline run and a San2Patch case use.

- **fixPOV: 29 of 37 POVs blocked**, 12 of 16 cases fully blocked, mean 0.836. Blocked
  is good.
- **residual: 1 of 6 hardened.** Higher is better here too, but **0 is a perfectly good
  result** — a residual POV that still reproduces means the patch left exactly the hole the
  official upstream fix leaves open, which is the expected neutral outcome. The field names
  (`hardened_beyond_fix` / `matches_official_fix`) exist so no consumer renders that as red.
  See `../POV_SCORES.md`.

Every POV was re-run on the **unpatched** tree first; `reproduces_on_base` carries the result
per POV, and all 22 case/family builds came back `ok` on both sides.

## Environment fixes that were required and are not upstream

Recorded because a reader reproducing this will hit all of them: a guarded
`parse_other_error` in `nvwa/parser/address.py` (an *empty* sanitizer report — which is what a
**successful** patch produces — otherwise raises, and the patch is silently discarded), tool
error handlers, a `syz-symbolize` stub, two `pull.sh` remotes repointed to `vadz/libtiff` and
`gnutools/binutils-gdb` (both taken from `dataset/project_info.csv`), `/etc/debuginfod/
*.urls` removed from the image (`llvm-symbolizer` otherwise blocks ~180s per crash and
exceeds the harness's hardcoded 120s PoC timeout, which is reported as "no sanitizer report"
and *silently skips the case*), `httpx==0.27.2` pinned against the artifact's `openai==1.35.1`,
and a `libclang-16.so` symlink. Build and test must also use the identical container mount
path, or sanitizer-report normalization silently no-ops and cases vanish without error.

## POV re-scoring from the dashboard

Per-case "re-score this patch" buttons are wired, the same way San2Patch has them:
`baselines/patch_source.py` gained a `patchagent` entry in `_BASELINES` (three provider
functions, no change to the San2Patch ones), and `dashboard/backend/patchagent_fixpov.py`
mirrors `san2patch_fixpov.py`. Both families go through the same `fixpov replay-patch` CLI, the
same certified manifests and the same `_ReplayCheckout` reconstruction a pipeline run's own
POV replay uses, so a PatchAgent case, a San2Patch case and a pipeline run are measured by
literally the same oracle. Job bookkeeping is `run_jobs`, unmodified.

The base commit passed to the replay comes from `patch_source.benchmark_base`, which reads the
`base_revision` recorded when the run was normalized — skyset checks out a known commit, so
the base is exact rather than inferred. Labels are namespaced `patchagent-<key>` because all
three tools have a libtiff CVE-2017-7601 patch and an unprefixed label would have them share
one scratch checkout.

Because two CVEs can share one run, both keys resolve to the same `patch.diff` and each gets
its own verdict — which for libtiff `c421b99` genuinely disagree (2/2 blocked for
CVE-2016-5314, 0/2 for CVE-2016-3186, a different bug the model was never shown).
