# fixPOV completeness audit — checklist

## Status: first full pass complete (2026-08-05)

All 26 projects `fixpov status` counts, plus the 1 excluded-by-design anomaly
(`apache__dolphinscheduler_CVE-2022-34662_2.0.9`, see its row below), have now
had at least one completeness audit against this checklist's definition. 14 of
26 had a real gap (a partial patch would have scored 1.0 against the old set);
those are fixed and certified. See the tracking table for the per-project
verdicts and the recurring "official fix uses `startsWith` with no separator
boundary" bug found independently in 6 projects (plexus-archiver-2018, zip4j,
dolphinscheduler-26884, plexus-utils-2022, DependencyCheck, spark-2016), plus
2 other distinct uncertifiable residual bugs found *in the official fixes
themselves* — spark-2016's separate symlink/canonicalization gap, and
antisamy's live-NodeList removal-index bug — all documented in their
NOTES.md rather than forced into unwinnable POVs.

**This does not mean the work is done.** A first pass can miss things a
second pass with fresh eyes catches — treat this checklist as a living
document and keep running rounds. Good next steps: (a) a second full pass
now that the "official fix has its own residual bug" pattern is established,
specifically hunting for it in the 11 projects where round 1-3 audits
predate that pattern being named explicitly; (b) run `fixpov replay
--project <slug>` for every project with new POVs against existing accepted
pipeline runs, to see if any previously-"blocked" patch now scores lower;
(c) reconcile this branch with the unmerged provenance-pinning work (see
"Known blockers").

## Why this exists

`fixpov status` reporting `fully_certified: true` only proves that every POV
*currently in the manifest* reproduces on the unpatched code and is blocked by
`official_fix.patch`. It says nothing about whether that set of POVs covers
**every** exploit path the official fix actually closes. A patch that fixes a
subset of what the official fix fixes can still score 1.0 against an
incomplete set — which defeats the entire point of `fix_pov_eval` as a
trustworthy, non-gating measurement.

**Proven case:** `asf__commons-text_CVE-2022-42889_1.9` originally had 4 POVs,
all driving the `script:` default lookup through the four alert-traced
`replaceIn` overloads. The official fix commit
(`b9b40b903e2d1f9935039803c9852439576780ea`, "Remove dns, url, and script
lookups from defaults") removes **three** dangerous default lookups, not one.
A patch that stripped only `script:` and left `dns:`/`url:` live would have
scored 1.0 under the old set. The set is now a 3×4 matrix (12 POVs: script ×
dns × url, each through all four overloads) — see
`fix_povs/asf__commons-text_CVE-2022-42889_1.9/NOTES.md` for the
worked example and matrix-table format to copy.

## Definition of "complete" (read this literally, not loosely)

**The goal is a POV set that completely distinguishes the official-patched
version from the buggy version — every POV must reproduce (exit 0) on the
buggy revision and be blocked (non-zero) specifically by the behavior the
official fix introduces, and every behavior the official fix introduces must
be exercised by at least one POV.** Not "the headline vulnerability" — every
distinct hunk, every distinct guarded call site, every distinct default/
sub-feature the fix touches. A set that only proves the fix did *something*
is not the bar; a set that proves the fix did *everything the official patch
does, and nothing less* is the bar.

Operationally: a POV set is complete when, for every distinct behavior change
in the official fix commit(s) that closes an exploitable path, at least one
POV would still reproduce against a patch that fixed everything *except* that
one behavior. Put differently: if you can describe a plausible partial patch
that satisfies every current POV but plainly leaves the advisory's vulnerability
open, the set is incomplete.

## Per-project audit procedure

Run this for one project at a time.

1. **Pull the identity row** from `dataset/project_info.csv`:
   `advisory_id`, `cve_id`, `cwe_id`, `buggy_commit_id`, `fix_commit_ids`.
2. **Read the advisory in full** (GHSA + NVD). Note *every* distinct
   technique/vector it names — advisories often describe more than the
   headline example.
3. **Diff every fix commit against its parent** (all ids in `fix_commit_ids`,
   semicolon-separated — some CVEs have more than one). List every hunk that
   changes runtime behavior (skip tests/docs/comments). For each hunk, name
   the vector it closes: a new containment check, a removed default, an
   added restriction, a newly-guarded branch, a second call site the first
   fix commit missed.
4. **Cross-reference the finder alert** in `finder_results_filtered/`: list
   every `traces` source-to-sink path. These are a *lower bound*, not the
   ceiling — step 3 may surface fix hunks the alert never traced.
5. **Read the current POV set** (`fix_povs/<slug>/manifest.json` +
   `NOTES.md`). For each POV, write down: which vector from step 3 it drives,
   through which public entry point, with which payload shape.
6. **Build the coverage matrix**: rows = distinct vectors from steps 2–4,
   columns = existing POVs, cell = does this POV prove this vector is
   blocked? Any all-empty row is a gap.
7. **CWE-022 (path traversal / zip-slip) checklist** — check each even if the
   alert only traces one; verify empirically before assuming, don't guess:
   - relative `../` traversal, more than one depth
   - absolute-path entry (`/etc/...`, `C:\...`)
   - backslash-separated entries, if the library special-cases `\` (some do,
     e.g. zt-zip's `BackslashUnpacker`)
   - symlink-entry traversal (an entry creates a symlink pointing outside
     the destination, a later entry writes through it) — **only if the
     library's extractor actually materializes symlink entries as OS
     symlinks**; many pure-Java zip extractors of this era don't support
     symlink entries at all, so confirm behavior against the *unpatched*
     source before writing a POV around it
   - a second, distinct public extract/unpack entry point not already
     covered (zt-zip has three: `unpack`, `unwrap`, and iterate +
     `BackslashUnpacker` — the existing set already covers this, use it as
     the model)
   - shared-prefix partial-path bypass (`dest_evil` vs `dest`) — see
     `asf__karaf_CVE-2022-22932_4.3.5` for a certified example of this shape
8. **CWE-094 / "removes N default behaviors" checklist** — enumerate every
   sub-feature the fix disables or restricts, not just the one the alert
   traces; require a POV per sub-feature × per traced public entry point
   (the commons-text matrix is the template).
9. **Decide**: complete, or gap (list the missing matrix cells).
10. **If gap:** author new POV(s) under `povs/` per
    `fix_povs/GENERATING_POVS.md` (steps 2–4 there). Update
    `manifest.json` and `NOTES.md` — document the matrix the way
    commons-text's `NOTES.md` does. Certify:
    `python3 -m security_pipeline fixpov validate --project <slug>`, iterate
    until every POV is `certified: true`. **Never weaken a POV to force a
    certification** — if a vector genuinely does not reproduce on this
    codebase, say so in `NOTES.md` instead of faking it (see zip4j's
    "prefixed chain" honesty note — a variant they tried, confirmed doesn't
    reproduce for a structural reason, documented rather than hidden).
11. **If already complete:** add one line to `NOTES.md`'s coverage section —
    audit date + "reviewed for completeness against fix commit(s) X; no gap
    found" — so a future round doesn't redo the same read blind.
12. Update the tracking table below, commit (project-scoped commit — don't
    bundle unrelated projects), and **push immediately**
    (`git push origin gt-pov-extention`) — don't batch pushes until the end
    of a round.

## Round protocol

- Audit **5 projects at a time by default**, one per parallel agent, so
  Docker builds overlap instead of serializing; the remote server
  (`root@2.28.1.51`, `/root/autosec`, key `~/.ssh/tb`) has 8 CPUs / 16 GB.
  This has been pushed to **10 concurrent** at the user's request and it
  held up — no failed audits — but under that load `fixpov validate` can
  spuriously report `before_reproduced: 0` / `certified: 0` on a project
  that just finished certifying cleanly (observed once on `ff4j`, resolved
  by an immediate re-run). **Always re-run a failing/unexpected `fixpov
  validate` result once before treating it as real** — this is a Docker/
  container-contention artifact of concurrency, not evidence the POVs are
  broken. SSH/SCP calls can also transiently time out under this load;
  just retry. Also **give each agent's local commit-message file a unique
  name** (e.g. `/tmp/commit_msg_<project_slug>.txt`, not a shared
  `/tmp/commit_msg.txt`) — two concurrent agents writing the generic name
  raced and one clobbered the other's message file right before `git
  commit -F` ran (commit `9df8b64`, content correctly scoped, message text
  wrongly describes a different project). The commit *content* was
  unaffected since each agent still only staged/committed its own
  directory — only the message text is at risk from this race.
- Branch: `gt-pov-extention`, pushed to `origin/gt-pov-extention` — plain
  branch off `main`, **POV content only** (`fix_povs/` — no
  `security_pipeline/` or other code changes; see "Known blockers" for why
  the schema/provenance work from the old `feature/fixPOV-complete-
  commons-text` branch was deliberately left out). Continue committing
  rounds onto this same branch.
- Every project-scoped agent must run `fixpov validate` **with an explicit
  `--project <slug>`**, never unscoped/`--all` — an unscoped validate
  re-stamps every other project's `manifest.json` (timestamp/field churn)
  and that diff is easy to miss in review. (This happened once in round 1;
  reverted before commit.)
- After each round: `fixpov validate --project <slug>` for every touched
  project (re-verify independently, don't just trust the agent's self-report
  — same instinct as reviewing an LLM judge's output), then
  `fixpov replay --project <slug>` to refresh any already-accepted pipeline
  runs' `fix_pov/results.json` with the new POVs.
- One commit per project per round, pushed right after that commit — not
  batched at the end. This file's table update can ride in the last commit
  of the round or its own, also pushed immediately.

## Known blockers / deliberate scope decisions

- There is a **separate, older, unmerged branch**
  (`feature/fixPOV-complete-commons-text`) that did the commons-text
  completeness fix first, but bundled it with a provenance-pinning schema
  change (`vulnerable_revision` + `source_revision`/`content_hash` binding
  in manifest.json / `security_pipeline/fix_pov.py` /
  `manifest.schema.json`) touching `security_pipeline/cli.py` and
  `workspace.py` too. Merging that branch wholesale into `gt-pov-extention`
  produced real code conflicts (`CLAUDE.md`, `cli.py`, `workspace.py`) and
  is **explicitly out of scope for this branch** — the user wants
  `gt-pov-extention` to contain new/updated fixPOVs only, nothing else. Round
  0 (commons-text) was ported by taking only the final
  `fix_povs/asf__commons-text_CVE-2022-42889_1.9/` directory
  content from that branch's tip, re-validated clean against current
  `main`'s (unmodified) `fix_pov.py`. If the provenance-pinning
  infra is wanted later, that's a separate, deliberate PR — not something
  to pull in incidentally while adding POVs.
- `apache__dolphinscheduler_CVE-2022-34662_2.0.9` has a
  `fix_povs/` directory and a local project source, but does not
  appear in `fixpov status`'s 26-project count (which lists
  `CVE-2022-26884` for dolphinscheduler but not `CVE-2022-34662`). Unclear
  yet whether this is a broken manifest, a slug mismatch, or an intentional
  exclusion — worth one round to investigate before auditing it for
  completeness.

## Tracking table

Legend — **Verdict**: `?` not yet audited · `complete` no gap found ·
`gap→fixed` gap found and closed this round · `gap→open` gap found, not yet
fixed.

| # | project_slug | CVE | CWE | POVs (pre-audit) | Verdict | POVs (post) | Round | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | asf__commons-text_CVE-2022-42889_1.9 | CVE-2022-42889 | CWE-094 | 4 | gap→fixed | 12 | 0/1 (done, pushed) | script-only → script×dns×url matrix |
| 2 | codehaus-plexus__plexus-archiver_CVE-2018-1002200_3.5 | CVE-2018-1002200 | CWE-022 | 2 | gap→fixed | 4 | 1 (done, pushed) | Snyk Zip Slip family; absolute-path + symlink entries missed; official fix itself has a residual shared-prefix bug (documented, not certifiable) |
| 3 | srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2 | CVE-2018-1002202 | CWE-022 | 2 | gap→fixed | 3 | 1 (done, pushed) | Snyk Zip Slip family; directory-entry zip-slip missed; shared-prefix bypass reproduces even after official fix (documented, not certifiable) |
| 4 | zeroturnaround__zt-zip_CVE-2018-1002201_1.12 | CVE-2018-1002201 | CWE-022 | 3 | gap→fixed | 4 | 1 (done, pushed) | Snyk Zip Slip family; BackslashUnpacker's 4th (top-level-file) guard site missed by alert and POV |
| 5 | alibaba__one-java-agent_CVE-2022-25842_0.0.1 | CVE-2022-25842 | CWE-022 | 2 | gap→fixed | 3 | 2 (done, pushed) | 359603b is the real fix (deletes the vulnerable method); e0149bb confirmed a no-op version-bump commit. Old POVs both used entry names starting with `..`; a prefix-only `..` filter would've passed both — added a non-prefix `./../` traversal |
| 6 | apache__dolphinscheduler_CVE-2022-26884_2.0.5 | CVE-2022-26884 | CWE-022 | 4 | gap→fixed | 7 | 2 (done, pushed) | all 4 old POVs used one payload that tripped 2 of the guard's 4 ANDed clauses at once — no clause was individually isolated. Added 3 clause-isolating POVs. Shared-prefix `startsWith(dsHome)` bug found again in the official fix (documented, not certifiable) |
| 7 | apache__dolphinscheduler_CVE-2022-34662_2.0.9 | CVE-2022-34662 | CWE-022 | 0 | n/a — resolved | — | 4 (investigated) | NOT a gap: the directory has only a NOTES.md, no manifest.json (by design). The dataset's 2.0.9 base already contains the official fix (PR #10094 landed before the 2.0.9 tag) — `git apply --check` of the fix fails because the guards already exist, so there's no valid unpatched baseline to certify a POV against. Correctly excluded from `fixpov status`'s 26-project count. Already investigated and documented by a prior session; nothing to do here |
| 8 | apache__sling-org-apache-sling-servlets-resolver_CVE-2024-23673_2.10.0 | CVE-2024-23673 | CWE-022 | 2 | gap→fixed | 4 | 1 (done, pushed) | official fix guards both an absolute-path and a relative/deep-search branch in each of 2 methods; old POVs only drove the absolute-path branch of each |
| 9 | asf__commons-io_CVE-2021-29425_2.6 | CVE-2021-29425 | CWE-022 | 2 | gap→fixed | 4 | 1 (done, pushed) | manifest cited a non-existent fix SHA (`2736b6fe...`); real fix is `a62a5df26b080185a6c36db7fc652449bcc5536d` (PR #52) — old set only drove `normalize()`, missed `concat()` which is worse (discards base dir entirely, not just a stray `..`) |
| 10 | asf__karaf_CVE-2022-22932_4.3.5 | CVE-2022-22932 | CWE-022 | 2 | gap→fixed | 3 | 2 (done, pushed) | advisory names 2 sinks (OBR `FileUtil.unjar` + `karaf-maven-plugin` `RunMojo.extract`); finder alert only traced the first, old NOTES.md had wrongly scoped the second out. Karaf's fix DOES correctly use a separator boundary (confirmed NOT to have the startsWith bug seen elsewhere this round) |
| 11 | asf__tapestry-5_CVE-2019-0207_5.4.4 | CVE-2019-0207 | CWE-022 | 2 | complete | 2 (unchanged) | 4 (done, pushed) | `forFile` is `final` in `AbstractResource`, so every attacker-reachable entry point shares one guard, already covered. No separator-boundary bug (guard is exact `..` term-equality, not a prefix `startsWith`) |
| 12 | codecentric__spring-boot-admin_CVE-2022-46166_2.6.9 | CVE-2022-46166 | CWE-094 | 12 | complete | 12 (unchanged) | 4 (done, pushed) | confirmed genuine 1:1 matrix: 8 single-field notifiers (1 POV each) + MicrosoftTeams' 4 independently-evaluated fields (4 POVs) = 12, not redundant |
| 13 | codehaus-plexus__plexus-archiver_CVE-2023-37460_4.7.1 | CVE-2023-37460 | CWE-022 | 2 | complete | 2 (unchanged) | 2 (done, pushed) | unrelated to CVE-2018-1002200 — this fix is a dangling-symlink/TOCTOU guard, and this baseline already uses boundary-safe `Path.startsWith` (the 2018 CVE's `String.startsWith` bug was independently fixed by 4.7.1) |
| 14 | codehaus-plexus__plexus-utils_CVE-2017-1000487_3.0.15 | CVE-2017-1000487 | CWE-078 | 3 | gap→fixed | 6 | 4 (done, pushed) | old 3 POVs only drove `Commandline.execute()`; fix's main change is switching execute() off the shell entirely, so a partial patch there alone would pass all 3 while `getShellCommandline()` (still public, called directly) remained injectable. Added 3 POVs calling that method directly |
| 15 | codehaus-plexus__plexus-utils_CVE-2022-4244_3.0.23 | CVE-2022-4244 | CWE-022 | 2 | gap→fixed | 3 | 2 (done, pushed) | old set only drove the relative `../` branch of `FileUtils.resolveFile`; missed the absolute-path branch. Same `startsWith`-without-boundary bug found again in the official fix (documented, not certifiable) |
| 16 | diffplug__goomph_CVE-2022-26049_3.37.1 | CVE-2022-26049 | CWE-022 | 2 | complete | 2 (unchanged) | 4 (done, pushed) | uses `Path.startsWith(Path)` element-wise comparison — confirmed immune to the shared-prefix bug seen elsewhere (same safe idiom as karaf/plexus-archiver-2023/mpxj) |
| 17 | ff4j__ff4j_CVE-2022-44262_1.8.13 | CVE-2022-44262 | CWE-094 | 9 | gap→fixed | 10 | 4 (done, pushed) | 9 old POVs were genuinely distinct (not duplicates) but missed the fix's 10th guard site, `ConsoleOperations.updateFlippingStrategy` — a separately-routed HTTP admin action the old NOTES.md had wrongly excused as "covered by equivalence" |
| 18 | jeremylong__DependencyCheck_CVE-2018-12036_3.1.2 | CVE-2018-12036 | CWE-022 | 4 | gap→fixed | 6 | 4 (done, pushed) | 2 separate directory-creation guard branches (in `extractFiles` and `extractArchive`) had no POV — old 4 POVs only drove the file-write branches. Shared-prefix `startsWith`-without-boundary bug found again in the official fix (documented, not certifiable) |
| 19 | joniles__mpxj_CVE-2020-35460_8.3.4 | CVE-2020-35460 | CWE-022 | 3 | gap→fixed | 4 | 3 (done, pushed) | all 3 old POVs used entry names literally prefixed `../`; added a compound non-prefix traversal. Separator boundary confirmed CORRECT here (safe idiom, like karaf) |
| 20 | kubernetes-client__java_CVE-2020-8570_client-java-parent-9.0.1 | CVE-2020-8570 | CWE-022 | 2 | complete | 2 (unchanged) | 3 (done, pushed) | no separator-boundary bug (fix uses `normalize()==null` rejection, not a prefix `startsWith`, so that bug class structurally can't occur). Found and fixed an unrelated flaky-test bug: 2 POVs shared one scratch path, causing intermittent false failures |
| 21 | nahsra__antisamy_CVE-2022-28367_1.6.5 | CVE-2022-28367 | CWE-079 | 2 | complete | 2 (unchanged) | 4 (done, pushed) | serious residual bug found in the OFFICIAL fix: its cleanup loop removes children from a live NodeList by index while iterating, so it only ever hits odd-numbered original indices — a `<style>` tag with 3+ smuggled children still leaks an executable node past the "fixed" sanitizer. Reproduced end-to-end, documented (not certifiable — reproduces even after official_fix.patch) |
| 22 | perwendel__spark_CVE-2016-9177_2.5.1 | CVE-2016-9177 | CWE-022 | 2 | complete | 2 (unchanged) | 3 (done, pushed) | 2 uncertifiable residual bugs found and documented in the official fix: recurring separator-boundary bug on both guarded sites, plus a separate symlink/canonicalization bug (`getPath()` not `getCanonicalPath()`) — distinct root cause, unaffected by the fix |
| 23 | perwendel__spark_CVE-2018-9159_2.7.1 | CVE-2018-9159 | CWE-022 | 5 | complete | 5 (unchanged) | 3 (done, pushed) | all 3 fix commits audited (030e9d0 = byte-identical PR-merge of a221a86; a221a86 supersedes ce9e115); reduces to one 3-clause guard, only 1 clause (WEB-INF/META-INF) has a reachable exploit, already covered. No separator-boundary bug in this fix (though that bug shape exists elsewhere in spark from the unrelated older CVE-2016-9177) |
| 24 | rhuss__jolokia_CVE-2018-1000129_1.4.0 | CVE-2018-1000129 | CWE-079 | 6 | complete | 6 (unchanged) | 4 (done, pushed) | confirmed genuine 2x3 matrix (agent/core + agent/jvm) x (callback-streaming, callback-nonstreaming, mimeType); allow-list regexes verified unbypassable |
| 25 | undertow-io__undertow_CVE-2014-7816_1.0.16.Final | CVE-2014-7816 | CWE-022 | 3 | complete | 3 (unchanged) | 3 (done, pushed) | no separator-boundary bug here (fix uses `contains`, not prefix `startsWith`); encoded-slash bypass checked empirically and ruled out (default `ALLOW_ENCODED_SLASH=false` re-escapes) |
| 26 | vert-x3__vertx-web_CVE-2018-12542_3.5.3.CR1 | CVE-2018-12542 | CWE-022 | 3 | complete | 3 (unchanged) | 4 (done, pushed) | no separator-boundary bug (containment is structural via RFC-3986 `remove_dot_segments`, no `startsWith` anywhere); double-encoding bypass checked empirically and ruled out — only one decode pass is reachable here, unlike CVE-2019-17640's genuinely different mechanism. NOTE: commit `9df8b64`'s message text is wrong (says "goomph") due to a `/tmp/commit_msg.txt` filename collision between 2 concurrent agents — verified via `git show --name-only` that the commit's actual content is correctly scoped to this project only |
| 27 | vert-x3__vertx-web_CVE-2019-17640_3.9.3 | CVE-2019-17640 | CWE-022 | 2 | complete | 2 (unchanged) | 4 (done, pushed) | confirmed as an alternate-path-syntax bypass of CVE-2018-12542's fix (backslash separator, not an encoding-depth trick); fix is unconditional char substitution, no separator-boundary bug possible |

## Resuming after this round

1. `git -C /root/autosec fetch origin && git -C /root/autosec checkout feature/fixpov-completeness-audit && git -C /root/autosec pull` — check what round 1 actually landed (this table's "Round" column may lag the real commits; trust `git log` over the table if they disagree).
2. Pick the next 5 unaudited rows (verdict `?`), preferring ones sharing a
   CWE/vulnerability family when possible — it lets agents cross-pollinate
   technique the way the round-1 zip-slip trio does.
3. Spin up one agent per project, each given: the project's identity row,
   this file's audit procedure, and SSH access
   (`ssh -i ~/.ssh/tb root@2.28.1.51`, repo at `/root/autosec`, branch
   `feature/fixpov-completeness-audit`).
4. After all 3 report back, review their NOTES.md/manifest diffs, run
   `fixpov validate` yourself to confirm certification, commit, update this
   table, and replay against any accepted runs.
