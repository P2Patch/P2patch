# Residual gaps that upstream fixed later — SUPERSEDED

**This file no longer holds findings.** It was the 2026-08-15 hand-trace of seven
PoVs, and an independent audit on 2026-08-21 corrected six of its rows. Keeping a
corrected summary next to the stale prose it corrected was itself a hazard, so
the findings now live in generated artifacts that cannot drift from the evidence:

| what you want | where it is |
|---|---|
| every PoV at a glance, one row each | `residual_povs/REPORT.md` |
| one PoV in full, for manual audit | `residual_povs/reports/<suite>__<pov>.md` |
| the machine-readable record | `residual_povs/TRIAGE.json` |
| protocol, taxonomy, reasoning | `residual_povs/RESIDUAL_GAP_TRIAGE.md` |
| interactive view | dashboard → **Residual audit** |

Regenerate with `python3 residual_povs/triage/render_report.py`.

## What this file used to say, and why it was wrong

Recorded here because the *errors* are instructive — every one was a
release-attribution mistake, and none of them touched whether the gaps are real:

- **antisamy** — said the residual fix first shipped in v1.7.0, so three releases
  were exposed. It shipped in **v1.6.7**; two releases were exposed. The fix had
  been cherry-picked to the 1.6.x line as `32e27350`, and `git tag --contains`
  cannot see a cherry-pick.
- **DependencyCheck** — credited `a4b49354` (2023, v8.0.2, Δ 4y 8m). That commit's
  diff is purely additive. The sink the PoV drives was already safe at
  **v5.0.0-M1 (2019-02-17)**; Δ is ~9.5 months.
- **zip4j** — credited `c158768` with re-introducing the boundary-less check into
  2.x; it only canonicalised one operand. The real one is **`4c50a6a5`**,
  2019-05-18, *one day after* 1.3.3 shipped the fix. Also called
  `iris-sast/zip4j` a mirror: it is a synthetic repo of decompiled sources JARs.
- **cxf** — first release was given as 3.4.1 alone; the 3.3.x line got the same
  backport and **cxf-3.3.8** was tagged two hours earlier the same day.
- **yamcs** — claimed the 5.9.x line still shipped the gap at 5.9.12. It did not:
  5.9.x received a cherry-pick and **5.9.9 onward are safe**. What survives is
  sharper — **5.9.8.1 (2025-03-13)** still ships it, seven months after 5.10.0.
- **plexus-utils** — the Δ was right but the corroboration was incomplete: this
  gap later received **its own CVE, CVE-2025-67030 (HIGH)**.

**The methodology rule these produced:** never use `git tag --contains` to answer
"which release shipped the fix". It cannot see a cherry-pick onto a release
branch, so it reports the main-line tag and overstates user exposure. Read the
guarded file's content at each candidate tag, and confirm ancestry with
`gh api repos/<o>/<r>/compare/<sha>...<tag>`.
