# Running the POV scoring on the server

Scores every baseline tool's patches against our certified fixPOV / residual POV
manifests. See `baselines/COMPARISON.md` for *why*; this is the operational recipe.

## Why it runs on the server and not a laptop

The 36 project slugs in the plan are C/C++ (libtiff, libxml2, binutils-gdb, coreutils,
jasper, zziplib, libming, libjpeg-turbo, potrace, libarchive). Scoring one needs the
project's source clone under `dataset/project-sources/` **and** its Docker image.
A laptop has neither — the local clones are all Java. On the server both already exist,
because certifying the POVs built them.

## Setup — an isolated worktree

`/root/autosec` runs the dashboard and live pipeline runs. Do **not** switch its branch.

```bash
cd /root/autosec
git fetch origin feat/baseline-comparison
git worktree add -f /root/autosec-cmp origin/feat/baseline-comparison
cd /root/autosec-cmp
# project-sources is gitignored, so a worktree does not get it. Symlink, don't copy:
# 130 clones, and both trees must agree on the revision.
ln -s /root/autosec/dataset/project-sources dataset/project-sources
```

Reuse `/root/autosec/.venv/bin/python` — the worktree has no venv of its own, and the
pipeline is stdlib-only so nothing in it needs one.

**Clone the benchmark too**, or the base-commit check is dead weight:

```bash
cd /root/autosec-cmp/baselines && ./setup.sh san2patch-benchmark
```

`score_patches.py` reads each case's base commit from that clone's per-case `setup.sh`.
Without it every base reads `unknown`, which looks exactly like "the bases agree" while
being the opposite of a check — so the driver prints a `!!` line if it finds none.

## Run

```bash
cd /root/autosec-cmp
/root/autosec/.venv/bin/python baselines/score_patches.py san2patch --family fixpov --dry-run

setsid nohup bash baselines/scoring/run_scoring.sh > scoring.log 2>&1 < /dev/null &
setsid nohup bash baselines/scoring/finish.sh    > finish.log  2>&1 < /dev/null &
```

`run_scoring.sh` walks all four arms sequentially; `finish.sh` waits for it and renders
`baselines/POV_SCORES.md`. Both are `setsid`-detached, so an SSH drop (a closing laptop
lid) cannot signal them. Verify with:

```bash
P=$(pgrep -f "bash run_scoring.sh" | head -1)
ps -o pid,ppid,sid,cmd -p $P      # SID == PID and PPID == 1 means fully detached
ls -l /proc/$P/fd/1               # must be a FILE, not pipe:[...] (a dead ssh pipe)
```

## Two things that bite

**Disk.** Docker's volume sits at ~91%. Every project image already exists, so builds are
cache hits and add nothing — but point `--runs-dir` at `/` (228 G free), which
`run_scoring.sh` does, or the reconstruction checkouts (binutils is ~2 GB each) land on
the full volume.

**Pace.** ~3 min/case, not the ~30 s a single warm case suggests. Almost every case is a
distinct project slug — libxml2 `CVE-2016-1838` and `CVE-2016-1839` are different
revisions — so the per-project checkout reuse rarely helps and each case pays for a cold
ASan build. Budget ~3 h for the full 63.

## Reading the output

A case can end three ways and they must never be conflated:

| in the roll-up | means |
|---|---|
| `summary.score` | measured — a real number, including a real `0.00` |
| `skip_reason` | not applicable (tool found no patch, or we have no manifest yet) |
| `error` | **not measured** — the replay could not run |
| `base.state` | which commit the number was taken on |
| `oracle_drift` | the POV set changed after this score was taken — it is stale |

The third used to swallow San2Patch's two zziplib cases, whose benchmark sits on a
different revision than `project_info.csv`'s `buggy_commit_id`: CVE-2017-5974's diff names
a blob our clone does not have, and CVE-2017-5975's applied by context and then would not
compile. Both are now scored on their own base with the POVs re-proven there first, and
both produce real numbers — `0.00 (0/1)` and `1.00 (2/2)` respectively, verified on this
server. A `base.state` of `differs` is therefore normal and fine; `unresolved` means a ref
nobody has settled yet (see `patch_source.KNOWN_TAG_COMMITS`).

## Resuming

Re-running skips anything already scored, so an interrupted pass just continues.
`--force` re-scores; `--case <id>` isolates one; `--recheck-stale` re-scores only the cases
whose POV manifest has changed since — which is the one to reach for after a batch of POV
authoring, since "already scored" otherwise pins an old number forever.
