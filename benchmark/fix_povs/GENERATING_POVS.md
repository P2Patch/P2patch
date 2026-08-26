# Generating fixPOVs, project by project

This guide is written to be handed to a coding agent (Claude Code or similar),
**one project at a time**. Its job: produce a certified set of proof-of-concept
exploits for a single CVE that reproduce on the unpatched code and are blocked by
the official fix, covering **every** exploit path a complete fix must close.

> Prerequisite: the project's source must exist locally under
> `dataset/project-sources/<project_slug>/`. Check with
> `python -m security_pipeline fixpov list-projects`. Docker must be running.

---

## The exit-code contract (do not deviate)

Each POV is a command run inside the project container at `/workspace/repo`:

- **exit `0` ⇒ the exploit reproduced** (vulnerable behavior happened)
- **exit `2` (the reserved `error_exit_code`) ⇒ harness/build error** — classified
  ERRORED and excluded from the score. Your `run.sh` **must** map every build/
  compile/setup failure to this code (do not use `set -e`, which would leak the
  tool's own non-zero exit and be miscounted as "blocked").
- **any other non-zero exit ⇒ blocked** (a correct fix stopped it)
- always recompile the project **for the checkout under test** (never reuse a
  `target/` produced from a *different* source tree), so a POV tests the current
  patched source, never stale bytecode. The recompile happens once per checkout,
  not necessarily once per POV invocation — see "Build once per checkout" below.

Design each POV so the *same command* flips from 0 (unpatched) to non-zero
(patched) with **no change to the POV** — the only variable is the product code.

### Build once per checkout (the fast path)

`fixpov validate` / `replay` / the in-run `fix_pov_eval` stage all run a
project's POVs inside **one kept-alive container per checkout**, so container
startup, the mounted `target/`, and the container's `~/.m2` (plugin downloads)
are warmed once and reused by every POV — instead of a cold `docker run --rm` +
full recompile + re-download per POV.

To exploit that, give the manifest an optional `build_command` that compiles the
project **and** the POV drivers once, and make each per-POV `run.sh` **build-free
in the happy path**:

- `build_command` runs once, before any POV, in the shared container (e.g.
  `bash .security-pipeline/gtpov/run.sh __build__`). It should compile everything
  into a stable location that persists across `docker exec`s (e.g. `/tmp/...`) and
  drop a sentinel file (`BUILT`).
- each POV command (`run.sh <mode>`) checks the sentinel: if present it just runs
  `java` (fast, and safe to run **concurrently** with sibling POVs — read-only
  against `target/`, distinct output markers); if absent it **self-builds first**
  (a serialized `ensure_built`), so the POV still works standalone or if the
  persistent container couldn't start (the harness falls back to per-command
  `docker run --rm`, in which case POVs run sequentially).

With `build_command` set, POVs run concurrently up to `pov_parallelism`
(default `min(4, #povs)`; the runner still forces sequential when no persistent
container is active, so a fallback never launches several heavy builds at once).
See `ff4j__ff4j_CVE-2022-44262_1.8.13` (9 POVs, one `__build__`) and
`codehaus-plexus__plexus-utils_CVE-2022-4244_3.0.23` (2 POVs) for the pattern.
Projects **without** `build_command` still work unchanged — they just self-compile
per POV (now inside the warm shared container, so still cheaper than before).

Speed up certifying many projects with `fixpov validate --all --jobs N` (N
projects certified concurrently; `0` = auto from Docker's memory).

---

## Steps

### 1. Research the vulnerability

- Read the advisory: GHSA (`https://github.com/advisories/<GHSA-ID>`) and NVD
  (`https://nvd.nist.gov/vuln/detail/<CVE>`). The IDs are in
  `dataset/project_info.csv` (columns `advisory_id`, `cve_id`, `cwe_id`) and
  the finder alert under `finder_results_filtered/`.
- Read the **fix commit(s)** (`fix_commit_ids` in `project_info.csv`). The diff is
  the fixPOV for *what* the vulnerability is and *which paths* the fix
  guards. `dataset/fix_info.csv` names the changed file/class/method.
- Read the finder alert JSON: each `traces` array is a source-to-sink path, and
  the alert defines the scope the patcher is actually given.

### What "complete" means for a CVE (read this before adding a second POV)

A CVE is **not** defined per sink, and not per source. It is an identifier for
one specific security flaw — a **root cause plus the behavior it affects** —
whose extent is delimited by the official fix. A static-analysis finding *is* a
source-to-sink pair; a CVE is not. Enumerating sinks is therefore the wrong
completeness test, and applying it produces sets that measure the wrong thing.

The test to apply instead:

> Does this POV set **discriminate** a complete fix of *this flaw* from a
> plausible incomplete one?

Three rules follow.

1. **Add a POV only when it discriminates.** The justification is never "that's
   another sink" — it is "a realistic partial fix passes one of these and fails
   the other". Same root cause duplicated across copies the fix closes together
   counts (`CVE-2017-14745`: the identical unchecked `dynrelcount` in
   `elf32-i386.c` and `elf64-x86-64.c`; a patch fixing one copy has not fixed the
   CVE). So do distinct reachability paths a partial guard would miss
   (`CVE-2016-9264`'s three sample-rate tables, potrace's six readers). Two POVs
   that can only ever flip together are redundant no matter how many traces the
   alert lists.

2. **Sharing a fix commit is not identity.** One upstream commit routinely closes
   several distinct CVEs — libtiff `3144e57770` covers 7595/7596/7597/7599/7600/
   7601/7602; libming `3a000c7` covers ~8; zziplib `03de3be` covers 5974 and
   5976. "The commit message names CVE-X" is weak evidence that a given POV *is*
   CVE-X. Check the advisory's root cause, and cross-check the finder alert. A
   POV for a sibling flaw that merely shares the commit does not belong in this
   CVE's scored set: it makes the score answer "did the patch fix everything this
   commit fixed?" and marks down a patcher that completely fixed its assigned
   CVE. Keep such a POV if it is good work, but take it out of `povs[]` and say
   why in `NOTES.md` (see `gdraheim__zziplib_CVE-2017-5974` and
   `vadz__libtiff_CVE-2016-10092`).

3. **Trim `official_fix.patch` by flaw — and keep it complete for that flaw.**
   When one commit spans several CVEs, carry only the hunks that fix *this* one,
   so a POV is never blocked for a reason unrelated to the flaw being measured.
   But under-trimming is the dangerous direction: dropping a hunk that *is* part
   of this flaw's fix manufactures a false residual. `CVE-2017-14745` shipped a
   patch with only the `elf64-x86-64.c` half, so an i386 POV "still reproduced
   after the official fix" and certified as a residual gap — crediting patches
   for beating upstream on a hole upstream had closed. Diff your patch against
   the real commit before certifying.

### 2. Scaffold

```bash
cp -r fix_povs/_template fix_povs/<project_slug>
```

Fill in `manifest.json` (see schema below) and `NOTES.md` (advisory links + why
your POV set covers every path).

### 3. Write the POVs

- Put POV sources, fixtures, and a `run.sh`-style entrypoint under `povs/`.
- The whole `povs/` directory is copied into the container at
  `.security-pipeline/gtpov/`, so a manifest `command` looks like
  `bash .security-pipeline/gtpov/run.sh <args>`.
- Drive the **real** product code (public API, CLI, or request flow) — never
  simulate the vulnerable behavior with a fake assertion. Build inside the
  container against the mounted source (Maven deps are pre-populated in the
  image's `~/.m2`, so an offline build usually works; fall back to online).
- One POV per exploit path. If several paths share a driver, parameterize it
  (see the zip4j example — one Java harness, two manifest entries with different
  crafted inputs).

### 4. Capture the official fix as the "after" oracle

Produce `official_fix.patch` — a `git apply`-able diff (paths relative to the
repo root) that applies the official fix to the **local** project source. The
cleanest way to get one that applies to the decompiled dataset source:

```bash
S=dataset/project-sources/<project_slug>
# edit the vulnerable file(s) in $S to match the official fix, then:
git -C "$S" --no-pager diff -- <changed files> > fix_povs/<project_slug>/official_fix.patch
git -C "$S" checkout -- <changed files>   # revert; never commit the source edit
```

Match the source's line endings (some dataset sources are CRLF — edit in binary
if needed so the diff is minimal). Keep the patch to the security-relevant hunks.

### 5. Certify

```bash
python -m security_pipeline fixpov validate --project <project_slug>
```

This builds the image, runs every POV against the **pristine** source (must
reproduce, exit 0) and against the source **+ official_fix.patch** (must be
blocked, exit ≠ 0), and writes the `validation` block back into `manifest.json`.
A POV is `certified: true` only when it reproduces before and is blocked after.
Iterate until every POV is certified, then commit the whole
`fix_povs/<project_slug>/` directory.

### 6. Replay it against existing pipeline runs

If this POV set was authored after pipeline runs already completed, evaluate
those patched worktrees directly — there is no need to rerun the agents or the
rest of the pipeline:

```bash
# Replay against every accepted run for this project
python -m security_pipeline fixpov replay --project <project_slug>

# Or update one specific run
python -m security_pipeline fixpov replay --project <project_slug> --run <run_id>
```

This refreshes each run's `fix_pov/results.json`, Docker logs, and
`fix_pov_eval` entry in `state.json`, so the dashboard immediately shows
the new score. The replay remains non-gating: a reproduced exploit is recorded
as a missed path, without changing the run's accepted/rejected verdict.

### 7. Confirm it plugs into future pipeline runs

`python -m security_pipeline fixpov status` should show your project fully
certified. A subsequent `run` on that project's alert will show a
`fix_pov_eval` step and a `fix_pov/results.json` score.

---

## `manifest.json` fields

See `manifest.schema.json` for the full contract. Essentials:

- `project_slug`, `cve_id`, `cwe_id` — identity (slug must match the dataset).
- `advisory` — `{ ghsa, nvd, urls[] }`.
- `fix_reference` — `{ fix_commit_ids[], official_fix_patch, fix_summary }`.
- `sink`, `trust_boundary` — one-line root-cause statements.
- `setup_commands[]` — optional commands run once in the container before POVs.
- `build_command` — optional; compile the project + POV drivers once per checkout
  so each POV is build-free and POVs can run concurrently (see "Build once per
  checkout"). Omit it for the simple self-compiling-per-POV style.
- `pov_parallelism` — optional int; max POVs run concurrently when `build_command`
  is set (default `min(4, #povs)`; forced to 1 without an active persistent
  container).
- `povs[]` — each: `id`, `description`, `exploit_path`, `covers_alert_paths[]`,
  `command`, `reproduces_exit_code` (usually `0`). The `validation` block is
  filled by `fixpov validate` — don't hand-write it.

---

## Ready-to-paste per-project prompt

> You are authoring fixPOVs for **`<project_slug>`** (`<CVE>`,
> `<CWE>`). Source: `dataset/project-sources/<project_slug>/`. Advisory:
> `<GHSA>` / `<NVD-URL>`. Fix commit(s): `<fix_commit_ids>`.
>
> Follow `fix_povs/GENERATING_POVS.md` exactly. Read the advisory and
> the fix-commit diff, enumerate **every** source-to-sink path a complete fix
> must block (cross-check against the finder alert traces), and write one POV per
> path under `fix_povs/<project_slug>/povs/`, driving the real product
> code. Each POV command must exit 0 on the unpatched code and non-zero once
> fixed. Produce `official_fix.patch` (the official fix, `git apply`-able against
> the local source) as the certification oracle. Then run
> `python -m security_pipeline fixpov validate --project <project_slug>` and
> iterate until every POV is certified. Do not weaken a POV to make it pass — if
> a path can't be reproduced, say so in `NOTES.md` instead of faking it.
