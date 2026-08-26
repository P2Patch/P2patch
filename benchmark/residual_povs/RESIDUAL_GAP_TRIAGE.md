# Residual-gap triage — is the gap real, was it fixed later, is it live today?

**Status (2026-08-21).** Protocol defined 2026-08-15. **Coverage is now recorded
per POV in `TRIAGE.json`, not in this file** — this document is the protocol and
the reasoning; the machine-readable state lives next to it:

| artifact | written by | holds |
|---|---|---|
| `TRIAGE.json` | `triage/sweep_upstream.py` | the joined record, one row per POV |
| `triage/verdicts.json` | a human, via `triage/add_verdict.py` | status, later-fix commit, Δ, notes, evidence URLs |
| `verification/<slug>.json` | `python -m security_pipeline respov reverify` | **executed** outcomes per tree |
| dashboard → **Residual audit** | `dashboard/backend/residual_triage.py` | all three joined, with the commands to redo each row |

Run `python3 residual_povs/triage/sweep_upstream.py` to refresh the upstream
evidence for every suite; it never overwrites a human verdict.

**Corpus (2026-08-21):** 40 CVEs, **66 certified residual POVs**, 9 documented
negatives (suites with no manifest — a residual gap was searched for and none
found). This supersedes the "28 projects / 42 POVs / 4 negatives" header this
document carried: `6e1eab3` dropped 5 out-of-corpus suites on 2026-08-20 and 24
POVs were added before that. **`solon_CVE-2025-1584` is no longer a documented
negative** — it now carries two certified POVs.

**Analysis only** by the user's instruction — POVs and manifests are not edited
by this work. `respov reverify` was written specifically so the execution
evidence lands *outside* the manifests.

## What this document is for

`respov validate` proves a residual POV reproduces on the buggy tree *and* on
`buggy + official_fix.patch`. That is enough to use it as a **measuring
instrument** (did our patch close a hole upstream left open?). It is *not*
enough to make either of the two claims we actually want to publish:

| Claim | What it needs beyond certification |
|---|---|
| "our pipeline hardened beyond upstream" | the POV must be **falsifiable** — some tree where it goes `blocked` |
| "we found what upstream's fix missed" | the gap must survive in a **real shipped tree**, not just in `buggy + patch` |
| "this is a live vulnerability" | **reachability + impact** in the current release, then coordinated disclosure |

Each row of the ladder is strictly harder than the one below it. A POV can be a
perfectly good instrument and still not be a vulnerability. Keep the three
claims separate in the paper; conflating them is the most likely reviewer
attack.

---

## Corrections to the "three scenarios" framing

The starting hypothesis was: either (1) the POV is wrong, (2) the gap is real
and was fixed later, or (3) it is real and still live. That is the right spine,
but it is missing three things and one of them is load-bearing.

### 1. The `after` tree is synthetic — it may never have shipped

Certification applies `official_fix.patch` to `buggy_commit_id`. That tree is a
counterfactual: the *release* that carried the fix also carried every other
commit between the buggy revision and the tag. A residual POV can be certified
against `buggy + fix` and still be blocked in the release that actually shipped
the fix, because some unrelated commit closed it. So "the official patch was
incomplete" is a claim about **the fix hunks in isolation**, which is a weaker
and more contestable statement than "the fixed release was still vulnerable."

This produces a fourth outcome — `superseded-in-release` — and it must be
checked before any disclosure claim. (Note this cuts *for* us in the antisamy
case below: the residual fix landed one release after the CVE fix, so **two**
released versions — v1.6.6 and v1.6.6.1 — shipped with the gap open. The first
pass said three; corrected 2026-08-21 by reading the source at each tag.)

### 2. Certification has no negative control — a tautological POV certifies cleanly

The fixPOV oracle is two-sided: reproduce on buggy, blocked by the fix.
The residual oracle is one-sided — reproduce, reproduce. **Nothing in
`residual.certifies` requires the POV to be blocked by anything, ever.** A POV
that asserts a capability rather than a violation ("MD5 is still reachable
through this public API", "this constructor still leaves the sanitizer null")
would exit 0 on *every* tree, including a perfectly hardened one, and would
certify. It then silently scores every pipeline patch as "did not beat
upstream" for a reason that has nothing to do with the patch.

This is the real "scenario 1", and it is not "the test is buggy" — the test can
be technically correct and still be an unsound instrument. It needs its own
check (Stage 0 below), which certification structurally cannot provide.

### 3. "Incomplete fix" vs "adjacent weakness" is a distinction reviewers will attack

Roughly half of the corpus is a *sibling call site the fix did not reach* or a
*boundary bug inside the fix itself* — those genuinely support "the official fix
was incomplete." The rest exercise a weakness the advisory never claimed to
address (spark's symlink/canonicalization gap is a different root cause from its
traversal CVE; cuba's aggregate-quota exhaustion is not the per-upload size cap
the CVE reported). Both are fine as instruments. Only the first is honestly
described as an incomplete fix. Classify every POV as **in-scope** or
**adjacent** and use the right wording per row.

### 4. Two things the framing gets right and should be leaned on harder

- **"Fixed later" is not a weaker result than "still live" — it is often the
  stronger one.** When upstream itself later lands a commit closing exactly the
  path our POV drives, we get third-party confirmation that the gap was real and
  security-relevant, with a date attached. `Δt` between the official CVE fix and
  that later commit is a *detection-lead* metric: it is the number the paper
  wants. A live 0-day is one anecdote; "we flagged at t=0 what upstream fixed at
  t+4.9y, with their own commit calling it a path traversal vulnerability" is a
  measurement.
- **The recurring-class finding outranks any single instance.** One boundary bug
  (`startsWith` with no separator) appeared in 7 POVs across 6 projects in the
  first pass. On the current corpus it is **~18 POVs across ~9 projects**
  (adding yamcs ×7, hutool ×2, dolphinscheduler, seata — seata in the
  package-name domain rather than the path one). That systemic result survives
  even if individual rows get contested, and it is the part that generalizes.
  Any paper sentence saying "seven" or "six projects" is now an undercount.

### 5. Environment realism (from our own scaffold-failure history)

Containers run as **root**. A residual POV whose reproduction depends on writing
to a directory an unprivileged process could not touch is not exploitable in a
real deployment. Same trap as the permission-bit regression false-rejects. Check
before promoting anything to a disclosure claim.

---

## Outcome taxonomy (record one per POV, not per project)

| status | meaning | disposition |
|---|---|---|
| `unsound` | no tree makes it block — tautological instrument | exclude from residual score; report, do not disclose |
| `superseded-in-release` | blocked in the release that shipped the fix | valid instrument vs. the fix hunks; **no** upstream-miss claim |
| `fixed-later` | gap survived the release; a later upstream commit closed it | detection-lead datapoint; **best paper material** |
| `open-unreachable` | still in the code at HEAD, no attacker-reachable path | code-quality finding; report, usually not a CVE |
| `open-live` | still at HEAD and reachable with realistic preconditions | coordinated disclosure |
| `disputed` | maintainer says by-design / out of threat model | record verbatim; still valid as an instrument |

Per-POV granularity is required: DependencyCheck's two residual POVs land in two
different buckets (see findings).

---

## The protocol

Cheap stages first. Most POVs are resolved by Stage 2 without Docker.

### Stage 0 — Falsifiability (the missing negative control)

For each POV, find a tree where it **must** return `blocked`:

1. the later upstream commit that closes it (found in Stage 2) — re-run the POV
   there; it must go non-zero;
2. failing that, a hand-written minimal ideal patch, used as a scratch control
   and **not** committed to the POV directory;
3. if neither exists, ask: *does this POV assert a violated security property,
   or merely an observable capability?* If nobody can write a patch that makes
   it block without deleting the feature, mark `unsound`.

Deliverable per POV: one sentence naming the security property violated, in
terms a maintainer would accept.

### Stage 1 — Re-baseline against reality

Re-run the POV against, in order:

1. the actual fix commit's tree (`git checkout <fix_commit_id>`, not
   `buggy + patch`);
2. the first **released tag** containing that commit;
3. the release that the advisory names as fixed.

Blocked at (2) or (3) ⇒ `superseded-in-release`. Distinguish *blocked* from
*harness no longer builds* — the reserved exit 2 exists for that; a POV that
fails to compile against a refactored tree is `errored`, not evidence.

### Stage 2 — Upstream history triage (no Docker, minutes per POV)

This is where the numbers come from.

> **`git tag --contains <sha>` is a trap — do not use it to answer "which release
> shipped the fix".** It cannot see a cherry-pick onto a release branch, so it
> reports the *main-line* tag and silently overstates how long users were exposed.
> It is what produced this document's original antisamy error: `--contains
> 21c4061` answers v1.7.0, while the identical change had already shipped in
> **v1.6.7** as `32e27350` on the 1.6.x lineage (`compare 32e27350...v1.6.7` =
> 2 ahead / 0 behind; `compare 21c4061...v1.6.7` = *diverged*). **Read the guarded
> file's content at each candidate tag** — that is the only reliable oracle — and
> use `gh api repos/<o>/<r>/compare/<sha>...<tag>` to confirm ancestry.

1. Locate the guard at upstream `HEAD` (`gh api repos/<o>/<r>/contents/<path>`).
2. `git log -S'<guard expression>' -- <path>` to find the commit that changed it
   (clone full history; our `project-sources/` checkouts are `--depth 1`).
3. Map that commit → first release tag (`git tag --contains`).
4. Record: still-present-at-HEAD? fix commit + date + release; `Δt` from the
   official CVE fix; **does the later fix have its own CVE / advisory / issue?**
   (upstream calling it a vulnerability is the strongest possible corroboration);
   count of releases shipped with the gap open.
5. Check repo liveness (`archived`, `pushed_at`, successor repo). An archived
   repo changes the disclosure path, and a *moved* repo means HEAD is somewhere
   else — DependencyCheck's `jeremylong/` is archived; the live code is at
   `dependency-check/`.

### Stage 3 — Reachability & impact (only for still-open-at-HEAD)

A POV that drives an internal API proves a code-level gap, not a vulnerability.
Before any disclosure claim, establish:

- attacker-controlled input reaches the sink through a **public entry point of
  the product**, not just the library API;
- preconditions are realistic (who supplies the archive? who owns the sibling
  directory? does it need root?);
- a **trust boundary is actually crossed** — Jenkins treats Job/Configure as
  already-privileged, so a shell-injection through job config is by design;
- CVSS vector + a written attacker story + affected version range.

### Stage 4 — Disposition

- `fixed-later` → paper table row (Δt, corroborating commit/advisory). Also
  consider **promoting the POV to `fix_povs/`**: once a later upstream
  commit closes the path, the POV becomes certifiable under the two-sided
  oracle against *that* commit. That turns the residual corpus into a second,
  harder fixPOV tier at zero authoring cost.
- `open-live` → coordinated disclosure before publication: project security
  policy / GitHub private advisory, 90-day clock, CVE request, no POV details
  published until fixed or the clock expires. Dormant or archived projects still
  get a report; record the attempt and the date.
- `unsound` / `superseded-in-release` → exclude from the "beat upstream" score
  and say so; they remain valid regression instruments.

### Recording (suggested, not yet implemented)

Add per POV, in a **separate** analysis file rather than the manifest:
`upstream_status`, `later_fix_commit`, `later_fix_release`, `delta_days`,
`in_scope | adjacent`, `reachability`, `disclosure_state`. Then report the
residual score **partitioned by `upstream_status`** — because "beat upstream"
quietly means "matched upstream's *eventual* fix" for every `fixed-later` row,
and that is a different, weaker statement than beating the fix as shipped.

---

## Findings

**Not in this file.** Per-PoV findings are generated from the evidence and cannot
drift from it:

- `residual_povs/REPORT.md` — every PoV, one row each, with its three marks
  (`read` / `ran` / `ctrl`)
- `residual_povs/reports/<suite>__<pov>.md` — one self-contained dossier per PoV
- `residual_povs/TRIAGE.json` — the machine-readable join
- dashboard → **Residual audit** — the interactive view

The 2026-08-15 first-pass table that used to sit here covered 7 of the then-42
PoVs and had six release-attribution errors; it was removed on 2026-08-21 rather
than annotated, so nothing here can be quoted stale. What it got wrong, and the
rule that came out of it, is recorded in `FIXED_LATER_FINDINGS.md`.

The queue that used to follow is also gone: **all 66 PoVs are triaged.** Current
counts live in `REPORT.md`; regenerate everything with

```bash
python3 residual_povs/triage/sweep_upstream.py      # refresh upstream evidence
python3 residual_povs/triage/render_report.py       # rebuild overview + dossiers
```
