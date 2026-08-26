# <project_slug> — residual gaps in the official fix for <CVE>

- **CVE / CWE:** <CVE-XXXX-XXXXX> / <CWE-XXX>
- **Official fix:** `<commit id>` — the commit these POVs are proven to *survive*
- **Source of the finding:** `fix_povs/<project_slug>/NOTES.md`
  (completeness audit, <date>)

## What the official fix does

<Quote the guard the fix adds, and say plainly what it gets right.>

## What it still leaves open

<The residual gap, with the mechanism. Be concrete — name the check and why it
is insufficient, e.g. "`canonicalDest.startsWith(canonicalDir)` compares raw
strings with no trailing separator, so a sibling directory whose name begins
with the destination's name (`dest_evil` vs `dest`) satisfies the check while
resolving outside `dest`.">

## Coverage matrix

| POV id | Residual gap | Reproduces on pristine | Reproduces after official fix |
| --- | --- | --- | --- |
| `residual_1_...` | <gap> | yes (exit 0) | **yes (exit 0)** ← the certification |

## Verified not applicable

<Vectors checked against this codebase and ruled out, with the reason. Keep the
same honesty standard as the fixPOV notes: a vector that does not
reproduce is documented, never faked. A vector that IS closed by the official
fix belongs in `fix_povs/`, not here — say so and cross-reference.>

## Practical implication

A pipeline patch that blocks these is **stronger than the upstream fix** and
should be credited, not treated as diverging from the fixPOV oracle. A patch that
leaves them open merely matches upstream, which is the normal, acceptable
outcome.
