# VulnRepairBench

A benchmark for **automated vulnerability repair**: 101 real CVEs across 101
open-source projects, each pinned to its vulnerable commit, each buildable in a
container, and each scored by two independent families of curated,
machine-certified proof-of-concept exploits.

It ships inside the P2Patch repository, but nothing here depends on P2Patch —
the data, the Dockerfiles and the POV suites stand on their own.

| | count |
|---|---|
| CVEs / projects | 101 |
| Per-project Dockerfiles | 101 |
| fixPOV suites | 98 (325 POVs, 324 certified) |
| Residual-gap POV suites | 48 (67 POVs, 66 certified) |

Top CWEs: path traversal (CWE-022, 25), out-of-bounds read (CWE-125, 10),
buffer errors (CWE-119, 9), XSS (CWE-079, 8), OOB write (CWE-787, 7), code
injection (CWE-094, 6).

---

## What makes this different from a bug-fix dataset

Most repair benchmarks score a patch by whether it matches the developer's
fix, or by whether a test suite passes. Both are weak oracles: the first
punishes a *different but correct* fix, and the second says nothing about the
vulnerability. Here a patch is scored by **running real exploits against it**,
and every exploit's meaning is established by a mechanical certification
rather than by an author asserting it.

Two families, deliberately kept separate because they answer different
questions.

### `fix_povs/` — did the patch close the actual vulnerability?

A **fixPOV** reproduces on the unpatched code and is **blocked by the official
upstream fix**. That second half is the certification: it is what proves the
POV is measuring *this CVE* and not some unrelated breakage.

```
reproduces on vulnerable tree  AND  blocked after official_fix.patch  ->  certified
```

Coverage is per **exploit path**, not per sink — a suite exists to
*discriminate* a complete fix from a plausible incomplete one. Each suite's
`NOTES.md` carries the reasoning, including paths that were considered and
deliberately excluded.

Score: `blocked / (blocked + reproduced)`. Higher is better; 1.0 means the
patch closed every path the official fix closes.

### `residual_povs/` — did the patch beat upstream?

A **residual POV** reproduces on the unpatched code **and still reproduces
after the official fix**. It exploits a path upstream left open.

```
reproduces on vulnerable tree  AND  still reproduces after official_fix.patch  ->  certified
```

These are real. A completeness audit found the same
`canonicalDest.startsWith(dir)`-without-a-trailing-separator bug in **six**
projects' official fixes — a sibling directory sharing the destination's name
prefix still escapes — plus a sanitizer that removes children from a live
`NodeList` by index while iterating, leaking an executable node past the
"fixed" filter.

Score: `blocked / (blocked + reproduced)`, and here it is a **bonus, never a
deficiency**. `reproduced` means the patch has the same gap upstream does,
which is the expected, neutral norm. **A score of 0 is a perfectly good
result.**

### Why the inverted oracle matters

Dropping the "after" check would be the obvious simplification and it is
wrong. It is the only thing separating a genuine residual gap from (a) a
harness broken such that it always exits 0, and (b) a path upstream actually
*does* close — which belongs in `fix_povs/`, where it scores. So
`official_fix.patch` is **mandatory** for a residual suite, and optional for a
fixPOV one.

---

## Layout

```
dataset/
  project_info.csv     101 rows: slug, CVE, CWE, repo URL, buggy_commit_id, fix_commit_ids
  build_info.csv       per-project JDK / Maven / Gradle / build + test command / platform
  fix_info.csv         fix localization: changed file, class, method, line ranges
  Dockerfiles/<slug>/  per-project build image
  project-sources/     (gitignored) checkouts, reconstructed on demand

fix_povs/<slug>/
  manifest.json        POV ids, commands, exit-code contract, certification block
  official_fix.patch   the upstream fix, as the certification oracle
  povs/                POV sources, fixtures, run.sh
  NOTES.md             advisory analysis + why this set is path-complete

residual_povs/<slug>/  same shape, plus `residual_of` and per-POV `gap_summary`
  verification/        independent re-verification of residual claims
  triage/              upstream-status sweep + human verdicts (TRIAGE.json)
```

## The exit-code contract

Every POV is a command run inside the project container at `/workspace/repo`:

| exit | meaning |
|---|---|
| `0` | the exploit **reproduced** |
| `2` | harness/build error — recorded `errored`, **excluded from the score** |
| any other non-zero | **blocked** |

The reserved error code is load-bearing. "Non-zero == blocked" is a dangerously
forgiving default: a POV that exits 1 because no class file was ever produced
is not a blocked exploit. Staging failures are therefore detected by the
harness, not self-reported — if a `setup_commands` entry or the `build_command`
fails, every POV is recorded `errored` and the score is `null`.

## Certification is sealed

Each POV's `validation` block carries a `content_hash` fingerprinting the POV
sources, its command, the exit-code contract, `official_fix.patch`, and the
revision. Editing a POV after certifying it **invalidates** the certification
rather than silently inheriting it. Certification is created by the validators,
never hand-written.

## Getting the project sources

`project-sources/` is gitignored — the commit id is the record. Reconstruct a
checkout with the repo URL and `buggy_commit_id` from `project_info.csv`:

```bash
git clone --depth 1 <github_url> dataset/project-sources/<slug>
git -C dataset/project-sources/<slug> fetch --depth 1 origin <buggy_commit_id>
git -C dataset/project-sources/<slug> checkout <buggy_commit_id>
```

`buggy_commit_id` is always a full 40-character SHA, and that is not incidental:
an abbreviated SHA cannot be fetched at all, and a tag name fetches but creates
no local ref, so the checkout then fails. P2Patch automates this with
`python -m security_pipeline fetch --project <slug>`.

## Authoring new suites

See `fix_povs/GENERATING_POVS.md`, `fix_povs/AUTHORING_NEW_CVE.md`, and
`residual_povs/GENERATING_RESIDUAL_POVS.md`. The rule both guides share: **do
not weaken a POV to make it pass.** If a path cannot be reproduced, or a
residual gap turns out to be closed upstream, record that in `NOTES.md` — a
rigorous negative result is a valid result, and a forced POV corrupts every
score derived from it.
