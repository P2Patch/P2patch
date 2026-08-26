# Residual-gap POVs

Curated exploits for paths a CVE's **official upstream fix does not close**. They
are the mirror image of `fix_povs/`: fixPOV asks *"did the patch
match the official fix?"*; residual asks *"did it **beat** the official fix?"*.

These exist because real, released official fixes ship with gaps. Six official
fixes in this dataset use a bare `startsWith` containment check with no
trailing-separator boundary (a sibling directory sharing the destination's name
prefix still escapes); antisamy's official fix removes children from a live
`NodeList` by index while iterating, so a `<style>` tag with 3+ smuggled children
still leaks an executable node. A pipeline patch that closes one of these is
strictly stronger than upstream — this set is how that gets measured.

## The inverted oracle

A residual POV can't be certified the way a fixPOV is — it reproduces
against the official fix *by definition*, which is the whole point. So the
certification contract is inverted:

```
fixPOV:  reproduces on unpatched  AND  BLOCKED by official fix     → certified
residual POV:      reproduces on unpatched  AND  STILL REPRODUCES after it   → certified
                                                  ^^^^^^^^^^^^^^^^^^^^^^^^^
                             proves the official fix genuinely leaves it open
```

The "still reproduces after the official fix" check is load-bearing: it's the
only thing separating a genuine residual gap from (a) a broken harness that
always exits 0, and (b) a path the official fix *does* close (which is a
fixPOV, not a residual one). So `official_fix.patch` is **mandatory**
here — unlike fixPOV, where it's the "after" oracle but a POV can exist
without it.

## Scoring is a bonus, never a deficiency

- `blocked` → the patch closed a hole upstream left open. **Credit.** ✅
- `reproduced` → the patch has the same gap upstream does. **Expected, neutral —
  not a failure.** Matching the official fix is exactly what the fixPOV
  score already rewards.
- `errored` → inconclusive (build/harness failure, timeout, stale certification).

`score = blocked / (blocked + reproduced)` reads as "of the holes upstream left
open, what fraction did this patch also close". **A score of 0 is a perfectly
good result.** The dashboard renders it as a **Beyond** column, colored neutral
at 0 and green above it — never red.

## Layout

```
residual_povs/
  README.md                    # this file
  GENERATING_RESIDUAL_POVS.md  # how to author a project's residual POVs
  manifest.schema.json         # the manifest contract (adds `residual_of`, `gap_summary`)
  _template/                   # copy-me scaffold
  <project_slug>/
    manifest.json              # `residual_of` = the official fix commit these survive
    official_fix.patch         # mandatory — the "after" oracle for the inverted check
    NOTES.md                   # the gap mechanism + coverage matrix
    povs/                      # POV sources + run entrypoint (staged at .security-pipeline/respov/)
```

## Commands

```bash
python -m security_pipeline respov status                    # certification per project
python -m security_pipeline respov validate --project <slug> # certify: reproduces before AND after the official fix
python -m security_pipeline respov replay  --project <slug>  # score existing accepted runs
python -m security_pipeline run ... --no-residual-eval       # drop the stage for a run
```

In a pipeline run, residual POVs are scored automatically as the last stage
(`residual_eval`, after `fix_pov_eval`). It is **non-gating** — it can never
turn an accepted patch into a rejection.

See **GENERATING_RESIDUAL_POVS.md** to author a set, and
**`../fix_povs/AUTHORING_NEW_CVE.md`** for the full new-CVE workflow that
places this in context (it is Phase 3 there).
