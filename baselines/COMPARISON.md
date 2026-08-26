# Comparing the baselines — what the problem actually is

Three tools now have results in this repo:

| tool | who ran it | benchmark | headline it reports |
|---|---|---|---|
| **San2Patch** (USENIX Sec '25) | us, 2026-08-14 | VulnLoc, 39 cases | 32 / 39 repaired |
| **LoopRepair** (ICSE '26) | Sina — *separate work, listed for context only* | VulnLoc**+**, 40 cases | 30 / 40 repaired |
| **P2Patch** (ours) | ongoing | IRIS/Java CVEs | per-run verdicts |

Putting `82.1%` next to `75.0%` in a paper table would be wrong, for two independent
reasons. Neither is a bug in anyone's run — both are properties of how repair benchmarks
are usually reported, and both have to be fixed before the numbers mean anything.

---

## Problem 1 — the two tools did not attempt the same work

The benchmarks overlap but neither contains the other.

```
                San2Patch (VulnLoc)              LoopRepair (VulnLoc+)
                     43 ids                            40 ids
                        \                              /
        9 only S2  ──────┤        34 shared           ├────── 6 only LR
                        /                              \
```

- **34 ids appear in both lists**, but 2 of those (`CVE-2016-3186`, `CVE-2016-5314`) are
  in LoopRepair's set and **absent from San2Patch's shipped image**, so San2Patch never
  attempted them.
- **32 ids were genuinely attempted by both.** That is the only honest head-to-head
  denominator, and it is neither 39 nor 40.
- **6 ids are LoopRepair-only** — the "+" in VulnLoc+: `CVE-2016-1833`, `CVE-2018-18557`,
  `CVE-2020-27828`, `CVE-2021-3272`, `CVE-2022-4645`, `CVE-2022-48281`.
- **9 ids are San2Patch-only**: `CVE-2016-10094`, `CVE-2016-9273`, `CVE-2017-15020`,
  `CVE-2018-14498`, `CVE-2018-19664`, `gnubug-25003`, `gnubug-26545`, plus
  `bugchrom-1404` and `CVE-2017-9992` which neither could run.

### The comparable subset is 32 cases, not 39 and not 40

That is the only denominator on which the two tools could ever be compared. Per-case
outcomes for LoopRepair are its owner's to publish; this document does not restate them.

---

## Problem 2 — each tool grades its own homework, with a different grader

This is the more serious one, and it is the reason the fixPOV/resPoV work matters.

**LoopRepair's `verification.json`, for all 30 of its "patched" cases:**

```json
"tests": { "executed": 1, "passed": 1, "failed": 0 }
```

One test. That test is the crashing input itself. So LoopRepair's *repaired* means:
**the patch compiles, and the one PoC no longer crashes.**

**San2Patch's oracle is the same PoC check plus `make check`** — the project's own test
suite (`test_func.sh` in the benchmark: `make check -j$(nproc)`, with a tolerance for a
known-failing count). So San2Patch's *repaired* means: **the PoC no longer crashes, and
the project's real test suite still passes.**

San2Patch is therefore being graded harder than LoopRepair, and the two headline rates
are not on the same scale. A tool with a weaker oracle will score higher on identical
patches — which is exactly the direction the raw numbers point.

**Neither oracle asks the question we actually care about**, which is whether the patch
fixes the *vulnerability* rather than the *one input that demonstrates it*. A guard
narrow enough to reject exactly the PoC bytes passes both tools' checks and is still
exploitable.

---

## The fix: re-score every patch with one external oracle

We already have that oracle, and it is stronger than either tool's — the **fixPOV
POVs** (`fix_povs/`) and **residual-gap POVs** (`residual_povs/`). Each is a set
of hand-authored, certified exploit variants for one CVE:

- **fixPOV** — reproduces on the unpatched tree, *blocked by the official upstream fix*.
  Score = fraction blocked. This asks **"does the patch match upstream's fix?"** Multiple
  POVs per CVE deliberately probe past the single PoC: `CVE-2017-7600` has 8, `CVE-2017-7599`
  has 7, `CVE-2018-8806` has 6.
- **resPoV** — reproduces on the unpatched tree **and still reproduces after the official
  fix**. Score = fraction blocked. This asks **"did the patch beat upstream?"** A score of
  0 is the normal, expected result and is not a failure.

Applying the same manifests to a baseline's patches and to our own gives one grader for
both. That is the only comparison in this repo that would survive review.

**The machinery already existed** — `fixpov replay-patch` / `respov replay-patch`
(`security_pipeline/cli.py`) score an arbitrary caller-supplied diff against a project's
certified manifests, reconstructing the vulnerable tree from `buggy_commit_id` and
applying the patch, identically to how a pipeline run is scored. What was missing was a
way to run it over a whole benchmark rather than one case at a time; that is
`baselines/score_patches.py`.

---

## Coverage: do we have the POVs? Mostly yes.

| | count |
|---|---|
| VulnLoc-family cases across both tools | **49** |
| with a certified **fixPOV** POV set | **41** (81 POVs, all certified, 0 stale, 0 unsealed) |
| with a certified **residual** POV set | **5** (6 POVs) |
| with a `dataset/` Dockerfile | 43 / 43 rows present |

This is a much better position than the "our POVs are Java-only" assumption suggests —
the C/C++ POV harnesses are real, ASan-built, and certified (`bash .security-pipeline/FIXPOVKEEP/run.sh <id>`,
exit 0 == reproduced).

### The 8 gaps

**No `project_info.csv` row at all** (needs full onboarding — repo, commit, Dockerfile, POVs):

| case | attempted by | note |
|---|---|---|
| `CVE-2016-10094` | San2Patch only | libtiff |
| `CVE-2016-9273` | San2Patch only | libtiff |
| `gnubug-25003` | San2Patch only | coreutils |
| `gnubug-26545` | San2Patch only | coreutils |
| `bugchrom-1404` | neither | not in either image |
| `CVE-2017-9992` | neither | not in either image |

**Row exists, POVs not authored yet** (cheaper — only the POVs are missing):

| case | note |
|---|---|
| `CVE-2018-14498` | libjpeg-turbo; `buggy_commit_id` is the abbreviated `ae8cdf5` — expand to a full SHA first or it will not clone |
| `CVE-2018-19664` | libjpeg-turbo; same, `beefb62` |

Residual coverage (5/49) is thin, but that is expected and much less urgent: a residual
POV requires finding a hole the *official* fix left open, which does not exist for most
CVEs. Absence of a resPoV is not a gap in the way absence of a fixPOV is.

---

## What this changes about how we report

1. **Report the 32-case intersection as the head-to-head**, with the full per-tool sets
   as separate rows. Never compare 32/39 to 30/40 directly.
2. **Report each tool's own headline and its fixPOV score side by side.** The gap between
   them is itself the finding: it measures how much of each tool's claimed success is a
   PoC-shaped guard rather than a fix.
3. **State each tool's native oracle explicitly** in the table caption. "Repaired" means
   different things in the two papers, and a reader cannot recover that from a percentage.
4. **Treat single-run numbers as noisy.** Two of 39 San2Patch cases flipped outcome across
   identical runs. Any claim that one tool beats another by 1–2 cases is inside the noise.

## Result — San2Patch's own number is an upper bound

Full table in [`POV_SCORES.md`](POV_SCORES.md); raw per-case JSON under each case's
`fix_pov/results.json`.

| | San2Patch |
|---|---|
| claimed repaired (its own oracle) | 32 |
| scored against our fixPOVs | 26 |
| **fully blocked** | **17** |
| partial — an exploit variant still works | **9** |
| mean gt score | 0.753 |

**9 of the 26 scored patches leave at least one certified exploit variant working.**
These are not near-misses: `CVE-2016-1839` and `CVE-2016-5321` score **0.00** — the
patch stops the one PoC and closes none of the vulnerability.

On `CVE-2016-1839` the mechanism is visible in the diff. San2Patch caps entity-name
length at 1000 chars in `htmlParseName`/`htmlParseNameComplex` — but the bug is an
*underflow* at `xmlDictLookup(ctxt->input->cur - len, len)`, and the four certified POVs
trigger it with 4–20 byte names. The guard can never fire. It passed San2Patch's own
oracle because that oracle only re-ran the single PoC.

### 6 cases are excluded, not counted as 0

A patch that will not apply to our reconstruction produced no evidence either way.

| cases | cause |
|---|---|
| zziplib ×3 (`CVE-2017-5974/5/6`) | **Benchmark drift.** San2Patch sits on a different zziplib revision than `project_info.csv`'s `buggy_commit_id`; the blob its diff names (`007e7ce`) does not exist in our clone (ours is `1360354`). |
| jasper `CVE-2016-9557` | `buggy_commit_id` is the **tag** `version-1.90`, not a full SHA — the exact trap CLAUDE.md documents. Fixable: expand to the peeled commit. |
| `CVE-2016-10094`, `CVE-2016-9273`, `gnubug-25003`, `gnubug-26545` | No `project_info.csv` row, so no POVs exist for them yet. |

### On comparing against LoopRepair

LoopRepair is run, scored and analysed separately, by its owner, and its results live on
`main` under `baselines/runs/loop_repair/`. **Nothing in this document or this directory
reproduces, re-scores or restates them** — cross-tool comparison should be assembled
from both sets of numbers once each side is settled, not by one side copying the other's.

What is worth recording here is a methodological point that came out of both sides
scoring independently: on the cases where the two runs overlapped, they agreed score for
score and POV for POV. That is a real cross-validation of the oracle itself — the same
certified manifests, on different machines, by different people, produce the same
numbers. It says the measurement is reproducible, independently of what either tool
scored.

## How to run the scoring

```bash
# What would be scored, and the stated reason for every skip. No Docker, safe anywhere.
python3 baselines/score_patches.py san2patch --family fixpov --dry-run

# The real thing (needs Docker + dataset/project-sources; run on the server).
python3 baselines/score_patches.py san2patch --family both

# One case, e.g. to debug a patch that will not apply:
python3 baselines/score_patches.py san2patch --family fixpov --case CVE-2017-7601 --force
```

Each result lands at `<case dir>/fix_pov/results.json` (and `residual/`), which the
dashboard already reads — the `gt`/`res` badges on the Baselines page fill in as the run
progresses. A roll-up per baseline is written to `pov_scores_<family>.json` beside that
baseline's own results. Re-runs skip what is already scored, so an interrupted pass
resumes; `--force` re-scores.

**Current plan size** (from `--dry-run`, 2026-08-15):

| | fixPOV | resPoV |
|---|---|---|
| San2Patch | 28 patches | 3 |

31 scorings. Everything not in that count is skipped with a reason recorded in the
roll-up — mostly "tool reported no patch" (which is not a gap) and the 8 coverage gaps
below (which are).

## Order of work

1. Score both baselines' existing patches with fixPOV — nothing new to author, ~70 patches
   across 41 covered projects. **This is the highest-value step and it is blocked on
   nothing but compute.**
2. Score with resPoV where manifests exist (5 cases).
3. Author fixPOVs for `CVE-2018-14498` / `CVE-2018-19664` (rows exist; fix the short SHAs).
4. Onboard the 4 San2Patch-only cases with no row, if we want a complete San2Patch column.
5. Run our own pipeline on the same VulnLoc-family cases, so the third column is filled by
   the same grader. This is the real goal; the two baselines are the reference points.
