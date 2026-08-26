# Generating residual-gap POVs, project by project

A **residual POV** exploits a path the CVE's *official upstream fix does not
close*. It measures whether a pipeline patch is **stronger than upstream** — the
one thing the fixPOV score structurally cannot tell you, since that score
tops out at "matched the official fix".

> Prerequisite: the project's source must exist under
> `dataset/project-sources/<project_slug>/`, and you need an
> `official_fix.patch` that applies to it. Docker must be running.

---

## Where these come from

They are not invented. Each one is a finding from the completeness audit
(`fix_povs/COMPLETENESS_CHECKLIST.md`) that **could not be expressed as
a fixPOV**: `fixpov validate` certifies a POV by proving it is *blocked
by the official fix*, and these reproduce against it by definition. Until now
they lived only as prose in each project's `NOTES.md`. The recurring one:

> the official fix's containment check is a bare `canonicalDest.startsWith(dir)`
> with no trailing-separator boundary, so a **sibling directory sharing the
> destination's name prefix** (`dest_evil` vs `dest`) still escapes.

Start by reading the "residual"/"not certifiable" section of the project's
`fix_povs/<slug>/NOTES.md` — the analysis is already there.

## The inverted contract (this is the whole point)

```
fixPOV:  before = reproduced  AND  after = blocked      -> certified
residual POV:      before = reproduced  AND  after = reproduced   -> certified
                                              ^^^^^^^^^^^^^^^^^^
                        proves the official fix genuinely does NOT close it
```

`before` is the pristine source; `after` is the source with `official_fix.patch`
applied. The `after` run is the load-bearing one, and it is why
`official_fix.patch` is **mandatory** here (it is optional for fixPOV):
without it there is nothing separating a residual POV from an ordinary one.

Two things this catches that no-validation-at-all would not:

- a harness broken such that it always exits 0 — it would "reproduce" on a fully
  fixed tree, and every patch would look like it left the gap open;
- a path upstream *does* close — that is a fixPOV; put it in
  `fix_povs/` where it will actually score.

Exit codes are identical to fixPOV: `0` = reproduced (gap still open),
reserved `2` = harness/build error (ERRORED, excluded from the score), any other
non-zero = blocked (**the patch closed it — bonus**).

## Scoring: a bonus, never a penalty

| outcome | meaning | rendering |
|---|---|---|
| `blocked` | patch closed a hole upstream left open — **better than upstream** | credit (green) |
| `reproduced` | patch has the same gap upstream does — expected, fine | neutral, **not** a failure |
| `errored` | inconclusive (build failure, timeout, stale certification) | excluded from the score |

`score = blocked / (blocked + reproduced)`. **A score of 0 is a perfectly good
result** — it means the patch is exactly as good as the official fix. The number
only ever adds information about hardening *above* upstream. Never present it as
a deficiency, and never let it influence an accept/reject verdict: the stage is
non-gating by construction (`ResidualEvalStage` swallows every exception).

---

## Steps

### 1. Scaffold

```bash
cp -r residual_povs/_template residual_povs/<project_slug>
cp fix_povs/<project_slug>/official_fix.patch residual_povs/<project_slug>/
```

The official fix patch is usually identical to the fixPOV one — copy it
rather than re-deriving it, so both families certify against the same oracle.

### 2. Fill in `manifest.json`

Beyond the fixPOV fields, two are required:

- `residual_of` — the official fix commit id these POVs are proven to survive. A
  residual set is a claim *about a specific fix*; a set certified against one
  commit says nothing about a later hardening commit.
- per POV, `gap_summary` — one line on what the official fix fails to close.
  This is what the dashboard shows, so make it legible on its own.

### 3. Write the POV

Same mechanics as `fix_povs/GENERATING_POVS.md` (staging, `run.sh`,
`build_command` fast path) — the only differences are the directory
(`residual_povs/`) and the in-container stage path, which is
`.security-pipeline/respov/` rather than `.../fixpov/`, so a run evaluating both
families cannot have one clobber the other.

Drive the **real** product code, exactly as with fixPOV. For the recurring
shared-prefix case that means: extract into a destination directory `.../dest`
with an archive entry resolving to the sibling `.../dest_evil/<marker>`, and
assert the marker landed outside `dest`.

### 4. Certify

```bash
python3 -m security_pipeline respov validate --project <project_slug>
```

Iterate until every POV shows `certified: true`. **If a POV comes back
`after = blocked`, do not force it** — that means the official fix closes the
path, so it belongs in `fix_povs/` instead. Say so in `NOTES.md` rather
than weakening the POV; the same honesty rule as fixPOV, in mirror image.

**Before trusting a `certified: true`, diff `official_fix.patch` against the real
upstream commit.** That failure mode is loud — a POV that should be fixPOV
refuses to certify. The dangerous one is silent: an **incomplete**
`official_fix.patch` makes a POV reproduce "after the fix" for no reason other
than the missing hunk, and it then certifies as a residual gap. Because the
`after` run is the whole oracle here, a truncated patch does not error — it
manufactures a finding, and every run credits patches for beating upstream on a
hole upstream had already closed.

This is not hypothetical: `git__binutils-gdb_CVE-2017-14745` carried only the
`bfd/elf64-x86-64.c` hunk of `e6ff33ca`, whose own message says it checks the
return "in `elf_i386_get_synthetic_symtab` **and**
`elf_x86_64_get_synthetic_symtab`". With the complete commit as the oracle the
POV is blocked, and it is now a fixPOV. So: confirm the patch contains
**every** hunk of the upstream fix that touches this flaw — check the commit's
own `ChangeLog`/message for sibling functions and duplicated code copies — before
concluding a gap is real.

### 5. Confirm the wiring

`respov status` should show the project fully certified. Any subsequent pipeline
run on that project gets a `residual_eval` step and a
`security_pipeline_runs/<run>/residual/results.json`. Drop the stage with
`--no-residual-eval`.

If POVs are authored after runs already completed, score them without rerunning
the pipeline:

```bash
python3 -m security_pipeline respov replay --project <project_slug>
```

This reconstructs each accepted run's patched tree (`buggy_commit_id` + the run's
recorded `patch_only.diff`, falling back to the preserved worktree) and refreshes
its `residual/results.json`, so the dashboard's beyond-upstream score updates
immediately. Non-gating, exactly like `fixpov replay`.

---

## Ready-to-paste per-project prompt

> You are authoring **residual-gap POVs** for `<project_slug>` (`<CVE>`). A
> residual POV exploits a path the project's **official upstream fix does NOT
> close**. Read `residual_povs/GENERATING_RESIDUAL_POVS.md` first, then the
> "residual"/"not certifiable" section of
> `fix_povs/<project_slug>/NOTES.md` — the gap is already analyzed
> there. Write one POV per distinct residual gap under
> `residual_povs/<project_slug>/povs/`, driving the real product code. Each must
> exit 0 (reproduce) **both** on the pristine source and with
> `official_fix.patch` applied — that is what certification checks. Then run
> `python3 -m security_pipeline respov validate --project <project_slug>` and
> iterate until every POV is certified. If a POV turns out to be *blocked* by the
> official fix, it is a fixPOV, not a residual one — do not weaken it
> to pass; record the finding in `NOTES.md` instead.
