# VulnLoc — full dataset, all 43 ids, with per-case outcome

Generated from `aggregate.json`. This is the complete `vulnloc` list as it appears in
San2Patch's own `run.py`, **in that order**, so rows line up with the paper without a
mapping step. `INDEX.md` is the same data sorted by outcome, with links to each case's
log and patch. Project names for the 39 attempted cases are read out of the benchmark
paths in their own logs; the four absent ids have no log, so theirs are marked `?` — they
come from the public CVE record, not from this run.

| # | case | project | outcome | tries | time | cost | why not repaired | re-run? |
|---|---|---|---|---|---|---|---|---|
| 1 | `CVE-2017-14745` | binutils | harness-fault | 5 | 9m49s | $0.73 | harness: the case's `src/` tree is unusable, so `git reset --hard` fails and every candidate patch is unappliable | only after fixing the image |
| 2 | `CVE-2017-15020` | binutils | repaired | 1 | 4m39s | $0.22 |  | no |
| 3 | `CVE-2017-15025` | binutils | repaired | 1 | 4m11s | $0.20 |  | no |
| 4 | `CVE-2017-6965` | binutils | repaired | 1 | 10m34s | $0.43 |  | no |
| 5 | `gnubug-19784` | coreutils | repaired | 1 | 5m49s | $0.16 |  | no |
| 6 | `gnubug-25003` | coreutils | repaired | 1 | 12m05s | $0.21 |  | no |
| 7 | `gnubug-25023` | coreutils | repaired | 3 | 49m22s | $0.70 |  | no |
| 8 | `gnubug-26545` | coreutils | repaired | 1 | 16m06s | $0.23 |  | no |
| 9 | `bugchrom-1404` | chromium? | not-in-image | – | – | – | no `vuln/bugchrom-1404.json` in the image — San2Patch never dispatches it | no |
| 10 | `CVE-2017-9992` | ffmpeg? | not-in-image | – | – | – | no `vuln/CVE-2017-9992.json` in the image — San2Patch never dispatches it | no |
| 11 | `CVE-2016-8691` | jasper | repaired | 1 | 2m35s | $0.19 |  | no |
| 12 | `CVE-2016-9557` | jasper | repaired | 1 | 3m47s | $0.21 |  | no |
| 13 | `CVE-2016-5844` | libarchive | repaired | 1 | 2m49s | $0.14 |  | no |
| 14 | `CVE-2012-2806` | libjpeg | repaired | 2 | 8m34s | $0.47 |  | no |
| 15 | `CVE-2017-15232` | libjpeg | repaired | 1 | 5m36s | $0.28 |  | no |
| 16 | `CVE-2018-14498` | libjpeg | not repaired | 5 | 26m59s | $1.39 | genuine: patch built and applied, PoC still crashed after all 5 tries | no |
| 17 | `CVE-2018-19664` | libjpeg | not repaired | 5 | 31m31s | $1.58 | genuine: patch built and applied, PoC still crashed after all 5 tries | no |
| 18 | `CVE-2016-9264` | libming | repaired | 1 | 3m30s | $0.12 |  | no |
| 19 | `CVE-2018-8806` | libming | repaired | 1 | 12m14s | $0.37 |  | no |
| 20 | `CVE-2018-8964` | libming | not repaired | 5 | 42m06s | $1.53 | genuine: patch built and applied, PoC still crashed after all 5 tries | no |
| 21 | `bugzilla-2611` | libtiff | repaired | 1 | 2m55s | $0.16 |  | no |
| 22 | `bugzilla-2633` | libtiff | not repaired | 5 | 17m28s | $0.95 | genuine: patch built and applied, PoC still crashed after all 5 tries | no (would be best-of-10) |
| 23 | `CVE-2016-10092` | libtiff | repaired | 4 | 23m42s | $1.02 |  | no |
| 24 | `CVE-2016-10094` | libtiff | repaired | 1 | 2m05s | $0.14 |  | no |
| 25 | `CVE-2016-10272` | libtiff | not repaired | 5 | 11m44s | $0.60 | genuine: patch built and applied, PoC still crashed after all 5 tries | no (would be best-of-10) |
| 26 | `CVE-2016-3186` | libtiff? | not-in-image | – | – | – | no `vuln/CVE-2016-3186.json` in the image — San2Patch never dispatches it | no |
| 27 | `CVE-2016-5314` | libtiff? | not-in-image | – | – | – | no `vuln/CVE-2016-5314.json` in the image — San2Patch never dispatches it | no |
| 28 | `CVE-2016-5321` | libtiff | repaired | 1 | 1m50s | $0.11 |  | no |
| 29 | `CVE-2016-9273` | libtiff | repaired | 2 | 12m44s | $0.56 |  | no |
| 30 | `CVE-2016-9532` | libtiff | repaired | 1 | 3m53s | $0.23 |  | no |
| 31 | `CVE-2017-5225` | libtiff | repaired | 1 | 2m41s | $0.16 |  | no |
| 32 | `CVE-2017-7595` | libtiff | repaired | 1 | 3m39s | $0.21 |  | no |
| 33 | `CVE-2017-7599` | libtiff | repaired | 1 | 3m05s | $0.16 |  | no |
| 34 | `CVE-2017-7600` | libtiff | repaired | 1 | 3m37s | $0.20 |  | no |
| 35 | `CVE-2017-7601` | libtiff | repaired | 1 | 7m45s | $0.30 |  | no |
| 36 | `CVE-2012-5134` | libxml2 | repaired | 1 | 4m34s | $0.22 |  | no |
| 37 | `CVE-2016-1838` | libxml2 | repaired | 1 | 3m09s | $0.12 |  | no |
| 38 | `CVE-2016-1839` | libxml2 | repaired | 1 | 5m20s | $0.25 |  | no |
| 39 | `CVE-2017-5969` | libxml2 | repaired | 1 | 4m09s | $0.21 |  | no |
| 40 | `CVE-2013-7437` | potrace | not repaired | 5 | 15m27s | $1.01 | genuine: patch built and applied, PoC still crashed after all 5 tries | no |
| 41 | `CVE-2017-5974` | zziplib | repaired | 5 | 30m44s | $1.76 |  | no |
| 42 | `CVE-2017-5975` | zziplib | repaired | 1 | 3m20s | $0.21 |  | no |
| 43 | `CVE-2017-5976` | zziplib | repaired | 2 | 9m22s | $0.48 |  | no |


## Summary

| bucket | n | counts toward the score? |
|---|---|---|
| repaired | 32 | yes — numerator |
| not repaired (genuine) | 6 | yes — denominator |
| harness fault (`CVE-2017-14745`) | 1 | counted as a failure, for denominator parity with the paper |
| absent from the image | 4 | no — excluded, as the paper also excludes them |
| **total in `run.py`** | **43** | **denominator = 39** |

## Is anything worth re-running?

**No, with one conditional exception.**

**The 4 absent ids — nothing to re-run.** They are not in the shipped image at all (no
`vuln/<id>.json`), so San2Patch never dispatches them and they leave no trace: no log
line, no `res.txt`, no error. 43 − 4 = 39, exactly the denominator the paper reports, so
these are their exclusions too, not a broken install here. Re-verified against the live
image:

```
$ docker exec san2patch ls /app/benchmarks/final/final-test/vuln/ | wc -l
66                      # 66 ids across all datasets; none of the 4 among them
```

**The 6 genuine failures — do not re-run.** These *are* the result. Each burned all five
retries with 90–226 real LLM calls, patches that built and applied, and a PoC that still
crashed. San2Patch's protocol — and the paper's — allows 5 tries; giving a case a sixth
through tenth because we did not like the outcome is best-of-N, and it would raise our
number above the paper's by changing the protocol rather than by measuring anything.

We already know what that would look like: `bugzilla-2633` and `CVE-2016-10272` were
re-run once (for an unrelated reason) and **both flipped to success**. Counting those
would read 34/39 instead of 32/39 — a 5-point swing bought entirely by selection.

**`CVE-2017-14745` — the one real gap, and it is the image's fault, not the tool's.**
Re-running it as-is costs ~10 min and $0.73 to fail identically, because the failure is
before the model's work can be evaluated at all: San2Patch generated five candidate
patches (389k input tokens spent), and each time the validation container could not
`git reset --hard` in `.../binutils/CVE-2017-14745/src`, so every patch was recorded
`patch_failed` without ever being compiled or tested. The other three binutils cases all
passed on try 1, so this is specific to this case's directory, not to binutils.

It is worth re-running **only if** the source tree is populated first — running that
case's own `config.sh`/`build.sh` inside the benchmark container. That would turn our
one non-result into a real 39th data point. It is the only outstanding item in this
dataset.

## What *would* be worth spending compute on

Not any individual case — **repetition of the whole set**. Two of 39 cases flipped outcome
across identical runs, so a single pass has meaningful variance and one run cannot say
whether 32/39 vs the paper's 31/39 is a difference at all. Three full passes would give a
mean and a spread, at roughly 3 × $17.49 ≈ $52 and ~7 h wall clock each. That is a
methodological upgrade; re-running the six failures individually is not.
