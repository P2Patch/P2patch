# Authoring a complete test set for a new CVE — start here

This is the end-to-end walkthrough for going from a bare CVE to a **complete,
certified evaluation set**: fixPOVs (does a patch match the official
fix?) plus residual POVs (does a patch *beat* it?), audited on both the **path**
and **technique** axes. Every other doc in these two directories is a deeper dive
on one phase; this ties them together in order.

The whole method rests on one idea — **the official fix is the oracle.** Every
POV is certified by what happens when the official fix is applied, never by a
human asserting it works. That is what makes the score trustworthy.

```
                         ┌─────────────────────────────────────────┐
   new CVE  ──────────▶  │ Phase 1  fixPOVs (path axis)   │
                         │ Phase 2  technique-completeness audit    │
                         │ Phase 3  residual POVs (beyond-upstream) │
                         │ Phase 4  (optional) mine exploiter POVs  │
                         │ Phase 5  certify · replay · dashboard    │
                         └─────────────────────────────────────────┘
```

## The two POV families at a glance

| | fixPOV (`fix_povs/`) | Residual (`residual_povs/`) |
|---|---|---|
| Question | did the patch **match** the official fix? | did the patch **beat** it? |
| Certifies when | reproduces on unpatched **AND blocked by** official fix | reproduces on unpatched **AND still reproduces after** official fix |
| A `reproduced` result means | the patch **missed** a real path — a miss | the patch has the **same gap upstream does** — neutral, not a failure |
| Score | `blocked / (blocked+reproduced)` — coverage | `blocked / (blocked+reproduced)` — beyond-upstream bonus |
| CLI | `fixpov validate|status|replay` | `respov validate|status|replay` |
| Guide | `GENERATING_POVS.md` | `../residual_povs/GENERATING_RESIDUAL_POVS.md` |

Both are **non-gating** run stages (`fix_pov_eval`, `residual_eval`): they
measure, they never reject a run.

---

## Phase 0 — Prerequisites

- Project source at `dataset/project-sources/<slug>/` (`fixpov list-projects`
  shows what's available; `python -m security_pipeline fetch` clones missing ones).
- Docker running.
- The identity row from `dataset/project_info.csv`: `cve_id`, `cwe_id`,
  `buggy_commit_id`, `fix_commit_ids`. `dataset/fix_info.csv` names the exact
  changed file/class/method.
- A `<slug>` that **matches the dataset slug exactly** (that's how a run resolves
  its POVs).

---

## Phase 1 — fixPOVs: cover every path (the path axis)

Full detail in **`GENERATING_POVS.md`**. The shape of it:

1. **Research the vuln.** Read the advisory (GHSA + NVD) and — most important —
   **diff every fix commit** in `fix_commit_ids` against its parent. The fix diff
   *is* the fixPOV for which paths a complete fix guards. Cross-reference
   the finder alert's `traces` (a lower bound on paths, not the ceiling).
2. **Scaffold:** `cp -r fix_povs/_template fix_povs/<slug>`.
3. **Write one POV per distinct source-to-sink path**, driving the **real**
   product API — never a simulated assertion. POV sources + a `run.sh` entrypoint
   go under `povs/`; they're staged into the container at
   `.security-pipeline/gtpov/`.
4. **Capture `official_fix.patch`** — the official fix as a `git apply`-able diff
   against the local source. This is the certification oracle.
5. **Certify:** `python -m security_pipeline fixpov validate --project <slug>`.
   It builds the project, runs every POV on the pristine source (must reproduce,
   exit 0) and on source+`official_fix.patch` (must be blocked, non-zero), and
   writes the certification into `manifest.json`. Iterate until every POV is
   `certified: true`.

**Then audit path completeness** against **`COMPLETENESS_CHECKLIST.md`** — this is
the step that turns "some POVs" into "a complete set". Its definition of done:

> for every distinct behavior change in the official fix, at least one POV would
> still reproduce against a patch that fixed everything *except* that one behavior.

It carries per-CWE checklists (for CWE-022: relative/absolute/backslash/symlink/
second-entry-point/shared-prefix; for CWE-094: every removed default/guard site).
If you can describe a plausible partial patch that passes your set but leaves the
vuln open, you're not done. **Never weaken a POV to force certification** — if a
path genuinely doesn't reproduce, document it in `NOTES.md` instead of faking it.

---

## Phase 2 — Technique completeness (the second axis)

Full detail in **`TECHNIQUE_COMPLETENESS.md`**. Path completeness asks "every
*path*?"; this asks "every *payload technique* for a path, where a partial patch
could block one and miss another?".

The decision hinges on the **shape of the official fix**:

- **Broad control** (SpEL context restriction, unconditional quoter, feature
  removal, canonicalization, allow-list) → it neutralizes all techniques at once,
  so a partial patch could block one specific technique and be caught only by a
  *different* technique POV. Enumerate the sibling techniques and add one POV each
  that (a) certifies against the official fix and (b) passes the **discrimination
  test** (you can name a plausible patch that blocks the techniques you already
  test but not this one). Example: spring-boot-admin's fix is
  `SimpleEvaluationContext` — it blocks `T(...)` type refs, `Class.forName`
  reflection, and `new` constructor invocation alike, so all three are
  discriminating gt techniques.
- **Specific filter** is rare as an *official* fix; when it happens the set is
  usually technique-complete once the path axis is done — record why.

Most fixes are broad controls, so most sets are **technique-complete by fix
shape** with one payload per path. Record that verdict in `NOTES.md`; it *is* the
audit result, not an omission.

---

## Phase 3 — Residual POVs: is the official fix itself incomplete?

Full detail in **`../residual_povs/GENERATING_RESIDUAL_POVS.md`**. Real official
fixes ship with gaps. This phase captures them so a pipeline patch that closes
one is *credited* for beating upstream.

Inspect `official_fix.patch` for the recurring weak patterns (all found in this
dataset's real upstream fixes):

- **`startsWith` containment without a trailing-separator boundary** — a sibling
  dir sharing the destination's name prefix (`dest_evil` vs `dest`) still escapes.
  Found in 6 official fixes.
- **uncanonicalized checks** — a guard on `getPath()` not `getCanonicalPath()`,
  so a symlink slips through.
- **stateful-iteration bugs** — antisamy's fix removes children from a *live*
  `NodeList` by index, so 3+ smuggled nodes leak.

For each candidate, apply the **inverted oracle**: does it reproduce on unpatched
**and still reproduce after** `official_fix.patch`? If yes → residual POV
(scaffold from `../residual_povs/_template`, certify with
`respov validate --project <slug>`). If the official fix *blocks* it, it's a
fixPOV (Phase 1), not residual. If it only bypasses a hypothetical weak
patch but the official fix handles it, it's neither — document and skip.

Residual scoring is a **bonus**: `reproduced` (same gap as upstream) is the
expected, neutral norm and never a failure; `blocked` means the patch is stronger
than upstream.

---

## Phase 4 — (Optional) Mine the pipeline's own exploiter POVs

If pipeline runs already exist for this CVE, the hardening exploiter's bypass
variants are a candidate source for **both** families — they explore techniques
and patch-specific gaps a manual read can miss. The variant descriptions live in
`security_pipeline_runs/<run>/agent_io/exploiter_harden_r*/output.json`.

Triage each variant through the same oracle — there is no shortcut around it:

| variant, tested on unpatched + official-fix | →  |
|---|---|
| reproduces unpatched · **blocked** by official fix · not a dup | new **gt** POV |
| reproduces unpatched · **survives** official fix · not a dup | new **residual** POV |
| only bypasses a pipeline patch (official fix blocks it, or it's not attacker-reachable) | **not promotable** — document, add nothing |

Expect most to be not-promotable: they attack a weaker pipeline patch, not the
CVE. A rigorous "not promotable, here's the evidence" is a valid result.

---

## Phase 5 — Certify, replay, and see it in the dashboard

```bash
python -m security_pipeline fixpov status            # every gt POV certified & eligible?
python -m security_pipeline respov status           # every residual POV certified?

# Score the new POVs against runs that already completed (no agents rerun):
python -m security_pipeline fixpov replay  --project <slug>
python -m security_pipeline respov replay --project <slug>
```

New pipeline runs score both families automatically as the last two stages
(`fix_pov_eval`, then `residual_eval`). The dashboard's run list shows a
**Coverage** column (fixPOV) and a **Beyond** column (residual); each run's
detail page shows the per-POV breakdown. `--no-fix-pov-eval` /
`--no-residual-eval` drop a stage independently.

---

## The non-negotiable rules (they're what make the score mean something)

1. **The official fix is the only oracle.** Never certify by human assertion.
2. **Never weaken or fake a POV to make it certify.** A path/technique that
   doesn't reproduce, or a "gap" the official fix actually closes, gets
   *documented in NOTES.md*, never forced into the manifest.
3. **Drive the real product code**, never a simulated assertion.
4. **`error_exit_code` (2) for build/harness failure** — never let a compile
   error leak a generic non-zero exit, or it's miscounted as "blocked".
5. **Two axes, not one.** Path completeness (Phase 1) *and* technique
   completeness (Phase 2) — a set can be path-complete and still miss a technique
   a partial patch would exploit.
6. **Two families.** fixPOV (match upstream) *and* residual (beat upstream)
   — the second exists because real official fixes are themselves incomplete.

## Doc index

| File | Phase | What it's for |
|---|---|---|
| `README.md` | — | fixPOV concept + contract + commands |
| `GENERATING_POVS.md` | 1 | step-by-step to author a gt POV set |
| `COMPLETENESS_CHECKLIST.md` | 1 | path-completeness audit + per-CWE checklists + per-project status |
| `TECHNIQUE_COMPLETENESS.md` | 2 | technique-completeness taxonomy + per-project audit |
| `../residual_povs/README.md` | 3 | residual concept + inverted oracle + commands |
| `../residual_povs/GENERATING_RESIDUAL_POVS.md` | 3 | step-by-step to author a residual POV set |
| `manifest.schema.json` (both dirs) | — | the manifest contract |
| `_template/` (both dirs) | — | copy-me scaffold |
