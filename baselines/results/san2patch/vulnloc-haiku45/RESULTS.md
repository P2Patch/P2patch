# San2Patch on VulnLoc — Claude Haiku 4.5, ToT

> **Looking for a specific case's log or patch? → [`INDEX.md`](INDEX.md)** — one row per
> CVE with direct links to its runtime log, its patch, and its reasoning traces.
> **Want all 43 ids with why each one did or did not repair? → [`DATASET.md`](DATASET.md)**,
> which also says, per bucket, whether anything is worth re-running (short answer: no,
> except `CVE-2017-14745`, and only after the image is fixed).
> Per-case runtime logs are in [`by-case/`](by-case/); the per-batch `run.log` files
> interleave five cases each, which is why the sliced ones exist.

Run 2026-08-14 on the project server. Baseline commit `a8c5ace939cd`, image
`acorn421/san2patch`, arm `tot` (the paper's full method), `--retry-cnt 5` (their default),
1 worker. Authoritative table: **`aggregate.tsv`** — everything below is derived from it.

## Headline

| | ours (Haiku 4.5) | paper (Table 1) |
|---|---|---|
| repaired | **32 / 39** | 31 / 39 |
| rate | **82.1 %** | 79.5 % |
| cost / case | **$0.45** | $0.48 |
| mean time / case | 10 m 34 s | 8 m 55 s |

Of the 38 cases that produced a valid attempt, 32 succeeded — **84.2 %**. The 82.1 % above
counts `CVE-2017-14745` (a packaging fault, below) as a failure so the denominator matches
the paper's.

Denominator is **39, not the 43** ids in `run.py`'s `vulnloc` list — see *Dataset gaps*.
`CVE-2017-14745` is counted as a failure here so the comparison matches the paper's
denominator, though it is a packaging fault rather than a repair failure (below).

## Cost is dominated by failures, not by cases

| outcome | n | cost each | share of spend |
|---|---|---|---|
| success | 32 | **$0.326** | 60 % |
| failure | 6 | **$1.177** | 40 % |

A failure costs **~4× a success** because it exhausts all 5 retries while a success
usually lands on try 1. So "cost per case" is largely a function of the failure *rate*,
not of per-attempt cost — quoting it alone compares billing, not method. Report cost per
success and per failure separately.

Total spend: **$17.49** for 39 cases.

## The six genuine failures

| case | tries | time | cost | mode |
|---|---|---|---|---|
| CVE-2018-8964 | 5 | 42 m | $1.53 | `vuln_test_failed` |
| CVE-2018-19664 | 5 | 32 m | $1.58 | `vuln_test_failed` |
| CVE-2018-14498 | 5 | 27 m | $1.39 | `vuln_test_failed` |
| CVE-2013-7437 | 5 | 15 m | $1.01 | `vuln_test_failed` |
| bugzilla-2633 | 5 | 17 m | $0.95 | `vuln_test_failed` |
| CVE-2016-10272 | 5 | 12 m | $0.60 | `vuln_test_failed` |

All six are `vuln_test_failed`: patches applied and built, but the PoC still crashed.
Each made 90+ LLM calls, so these are real attempts, not infrastructure faults.

## Two cases were attempted twice — the first attempt is counted

`bugzilla-2633` and `CVE-2016-10272` completed full 5-try attempts and failed, then were
re-run (because an API-limit incident was wrongly believed to have affected them) and
succeeded. **The first attempt is what this report counts.**

Counting the better of two complete runs would make it best-of-10 tries where San2Patch's
protocol — and the paper's — allows 5. Taking the successes instead would report 34/39
(87.2 %), which is the same data read with selection bias. `aggregate.json` lists both
outcomes under `attempted_twice`, and the second attempt's artifacts are still on disk.

That these two flipped outcome on a re-run is itself a finding: **San2Patch is stochastic
at the case level**, so a single run of the benchmark carries meaningful variance. Any
comparison against our pipeline should account for that rather than treating one run as
the tool's fixed score.

## Dataset gaps — read before quoting any denominator

**Four of `run.py`'s 43 vulnloc ids are absent from the shipped image** (no
`vuln/<id>.json`): `bugchrom-1404`, `CVE-2017-9992`, `CVE-2016-3186`, `CVE-2016-5314`.
San2Patch dispatches by walking its vuln directory, so these are **never attempted and
leave no trace at all** — no log line, no `res.txt`, no error. A batch handed 5 such cases
runs 3 and reports "Patching completed".

43 − 4 = 39, exactly the denominator the paper reports, so these are their exclusions too.

**`CVE-2017-14745` has no `src/` tree**, so every attempt dies in setup at
`git reset --hard`. It is the one case in `aggregate.tsv` marked `needs_rerun`; re-running
it costs ~10 min and $0.73 to fail identically. Counted as a failure above for comparability,
but it measures the image's packaging, not San2Patch.

## Timing caveat

The server is shared with the AutoSec pipeline, and load ranged from 0.3 to 9.8 on 8 cores.
`mean_load` and `contended` are recorded **per case** (sampled every 30 s across each case's
own window), because contention arrives and leaves mid-batch. **7 of 38 valid cases are
`contended`** (load > 70 % of cores) and their `duration_s` should be excluded from any
timing claim. Tokens, cost and outcome are unaffected by load.

The 10 m 34 s mean above is over the **31 uncontended cases** only.

## What was thrown away, and why it matters

An account usage limit was reached mid-run at 18:39 UTC. It did not fail the batch — it
**shredded** it: each remaining case burned all 5 retries in ~4 seconds and wrote a
`res.txt` reading `vuln_test_failed`, indistinguishable from a real failure. Twelve cases
were recorded that way.

All eight that were re-run after the limit was raised **succeeded**. Reporting the shredded
records would have claimed San2Patch fails 8 cases it actually solves — a 20-point error.

`aggregate.py` therefore decides validity by **whether tokens were actually spent**, not by
what `res.txt` says, and `run_batch.sh` now aborts at the first limit error so later cases
stay unrun rather than acquiring fake results.

## Layout

```
<batch>/
  manifest.json    model, image digest, commit, host, load, present/missing ids
  metrics.tsv      per case: status, tries, duration, tokens, cost, mean_load, contended
  triage.json      per non-success case: genuine | api_limit | harness | proxy_suspect
  summary.tsv      case_id, status, tries, has_patch
  run.log          full batch log
  usage.jsonl      per-call token counts from the metering proxy
  load.jsonl       load average sampled every 30 s
  gen_diff/<case>/ res.txt, *_success.diff (the patch), stage_0_N/ per-attempt candidates
```

Batch dirs prefixed `b`/`g` are just launch generations; a case re-run in a later batch
supersedes the earlier row, which `aggregate.py` resolves by preferring the valid one.

**Everything is here, including the raw traces.** The 80 `*_graph_output.json` files
(16 MB) are the complete LangGraph state per attempt — every stage's prompt-level reasoning,
the candidate patches it considered, and why one was selected. That is the material for any
qualitative analysis; nothing quantitative depends on it.

The server copy at `/root/autosec-baselines/san2patch/runs/` is identical.

## Reproduce

```bash
bash /root/autosec-baselines/san2patch/batches.sh remaining        # what is outstanding
bash /root/autosec-baselines/san2patch/batches.sh chain-remaining  # run it, gated, detached
python3 /root/autosec-baselines/san2patch/aggregate.py runs        # rebuild aggregate.tsv
```
