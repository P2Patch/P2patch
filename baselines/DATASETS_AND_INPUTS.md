# Datasets and inputs — where we are, and what a cross-comparison requires

_2026-08-12. Companion to `../BASELINE_COMPARISON.md` and `server_snapshot/README.md`._

---

## 1. The three papers' datasets

| | PatchAgent | San2Patch | LoopRepair |
|---|---|---|---|
| **Name** | (unnamed, 178 cases) | VulnLoc + San2Vuln | VulnLoc+ |
| **Size** | 178 vulns / 30 programs | 39 of 43 VulnLoc; 27 San2Vuln | 40 of 53 |
| **Composition** | 28 ExtractFix + 150 OSS-Fuzz/Huntr | VulnLoc (Shen et al.); San2Vuln = 27 post-Aug-2024 vulns they curated | 41 VulnLoc + 12 CrashRepair (Shariffdeen et al.) |
| **Language** | C/C++ (fork adds Java via Jazzer) | C | C/C++ |
| **Bug classes** | 9 memory-safety types | BO, IO, DTO, DZ, NPD, UAF | same 6 |
| **Exclusions** | 2 ffmpeg (irreproducible) | 4: bugchrom-1404, CVE-2017-9992, CVE-2016-3186, CVE-2016-5314 (would not reproduce under sanitizer instrumentation) | 13 (localization tool produced nothing) |
| **Ships PoCs?** | via OSS-Fuzz | **yes** — `san2patch-benchmark`, per case | yes |
| **Ships functional tests?** | manually collected, in artifact | **yes** — `test_func.sh` per case | no (no functional gate) |

These are three overlapping views of **one benchmark family**: VulnLoc ⊂ VulnLoc+ , and ExtractFix
overlaps VulnLoc heavily. That is why our C/C++ subset lines up with all three at once.

## 2. Our dataset

| | |
|---|---|
| `project_info.csv` | 256 rows — **213 Java, 43 C/C++** |
| Curated alerts in `finder_results_filtered/` | 77 — **36 Java, 41 C/C++** |
| Java provenance | CWE-Bench-Java / IRIS lineage; CodeQL-derived taint alerts |
| C/C++ provenance | **VulnLoc+ (see §3)** |
| Certified fixPOVs | 19 C/C++, plus the Java set |
| Runs on the deployment | 170 — 87 Java, **83 C/C++ (all 41 cases, both arms)** |

## 3. Where our C/C++ alerts came from — the answer, and a problem

### 3.1 The case list is VulnLoc+, essentially in full

Not a selection. Measured against `san2patch-benchmark/vulnloc-meta-data.json`:

- **37 of our 43** C/C++ cases are VulnLoc cases.
- **The other 6** — jasper CVE-2020-27828 / CVE-2021-3272, libtiff CVE-2018-18557 / CVE-2022-4645 /
  CVE-2022-48281, libxml2 CVE-2016-1833 — are exactly LoopRepair's "RED-TEAM" CrashRepair additions.
- So our C/C++ set **is** VulnLoc+: 43 cases against LoopRepair's 40 evaluated.
- Missing from ours: 4 VulnLoc cases (coreutils gnubug-25003, bugzilla-26545; libtiff CVE-2016-9273,
  CVE-2016-10094) and the 2 ffmpeg entries (CVE-2017-9992, bugchrom-1404) — ffmpeg isn't in our
  project list at all.

Added by Sina Marefat in `fe208b5` / `f2fbfb9` / `01a4f0a` (2026-08-08 → 08-09).

### 3.2 But the alerts themselves were hand-authored, not tool-generated

This is the part worth knowing, because it changes what our C/C++ results mean.

**The static-analysis toolchain cannot produce them.** IRIS's `build_codeql_dbs.py` (the upstream Finder toolchain, no longer vendored here) hardcodes
`--language java`, and the only query shipped is `packages.ql`. There is no C/C++ analysis path.

**And the alerts don't look like its output.** Measured across all 77 alert files:

| | Java alerts | C/C++ alerts |
|---|---|---|
| files | 36 | 41 |
| trace steps | 2976 (~83/file) | 158 (**~4/file**) |
| steps in IRIS form `expr : Type` | 2096 (**70%**) | 4 (**3%**) |
| mean `note` length | 159 chars | **788 chars** |

Java steps read `"path : String"` — a taint tracker emitting a variable and its type. C/C++ steps read
`"for (s = 0; s < spp; s++) : the read loop is bounded only by spp, dropping the && (s < MAX_SAMPLES) guard"`
— source text plus a human explanation of the defect.

**They encode the root cause, not just the symptom.** For libtiff CVE-2016-5321 our alert's 5 steps are
tiffcrop.c 5755 → 5932 → 6079 → 992 → 994. VulnLoc's sanitizer stack trace for the same case is only
994 → 6079 → 2278. Ours contains the crash frames **plus** the untrusted-tag read (5755), the
insufficient validation (5932), and the loop that dropped its bound (992) — i.e. the analysis a
repair tool is supposed to perform.

### 3.3 What follows

1. **Our C/C++ "alert-only baseline" is not an alert-only baseline in the sense the Java arm is.** It
   receives a curated root-cause writeup. Against San2Patch — whose entire input is a raw sanitizer
   log — we would be comparing with strictly *more* information, not less.
2. **It plausibly explains the C/C++ numbers.** `baseline` scored 41/41 accepted at 0.900 mean
   fixPOV coverage for $0.39/run. That is a suspiciously good result for an arm that is
   supposed to be the weak one, and this is the most likely reason.
3. **It is fixable, and the fix is a decision, not a bug.** Three options, in preference order:
   - **(a) Declare the regime honestly.** Rename the arm for C/C++ (e.g. `rootcause_given`) and report
     it as a distinct, *stronger*-input condition. Cheapest, and still scientifically meaningful —
     it upper-bounds what the patcher can do with perfect localization.
   - **(b) Author a degraded alert** per case containing only what a sanitizer log yields (crash
     frames + bug type, from `vulnloc-meta-data.json`'s `crash_stack_trace` / `bug_type`, which we
     already have). That is the true apples-to-apples input against San2Patch and PatchAgent.
   - **(c) Add a real C/C++ static-analysis path** (CodeQL C++ queries) so the alerts are generated the
     way the Java ones are. Most faithful to our own design, most work.

   **Recommendation: do (b) and keep (a).** Two alert tiers per case — `sanitizer-equivalent` and
   `rootcause-given` — turns an accidental confound into a deliberate ablation, and it is a few hours
   of scripting from data we already have.

## 4. Cross-comparison: what has to change on each side

### 4.1 Our Java dataset → their systems

| | PatchAgent | San2Patch | LoopRepair |
|---|---|---|---|
| Feasible? | partly | **no** | **yes — the only one** |
| Needs | Jazzer harness + OSS-Fuzz-style builder per CVE | a Jazzer log parser they don't have (their parsers are ASan/UBSan/MSan/TSan; the tool is C-focused) | vulnerable function + statement + a PoV |
| Blocker | ~46% of our Java CWEs (XSS 38, authn/authz ~20, info exposure) produce **no sanitizer-observable fault**; Jazzer has no XSS detector | same, plus no Java front end in the artifact | none structural |

**LoopRepair is the one to port to Java**, and the reason is that we already hold its inputs:

- `F_v` + `S_v`: LoopRepair gets these from CrashAnalysis. **Our IRIS alert already names the sink** —
  the last trace step is the vulnerable statement, and its `uri` gives the file. No localizer needed.
- PoV: **our exploiter already produces one.** LoopRepair's metric ("plausible" = all PoVs pass) maps
  exactly onto our `pov_after` gate.
- Its prompt is a generic "here is a vulnerable function, patch these hunks" — nothing C-specific.

That makes a genuinely fair Java comparison possible against at least one published system, on the
dataset we actually care about.

### 4.2 Their C/C++ dataset → our pipeline

**Already done** — all 41 cases, both arms, 83 runs, $108.47. What remains is correctness of the
comparison, not coverage:

1. **Fix the input regime** — §3.3(b), the sanitizer-equivalent alert tier. Without it, no C/C++
   number is comparable to San2Patch or PatchAgent.
2. **Wire real functional tests** — all 43 rows still have `test_command = true`. Port
   `san2patch-benchmark`'s `config_func.sh` / `build_func.sh` / `test_func.sh`. This is what makes
   our "accepted" mean the same thing as their "repaired". Their 7 cases with no usable suite come
   out of both denominators.
3. **Import the shipped PoCs** — see §5.

### 5. Should we generate PoVs? Mostly no — import them

| situation | what to do |
|---|---|
| Our pipeline on C/C++ | **Import, don't generate.** `san2patch-benchmark` ships a crash input per case (`tests/1.bin`, `crash_input` like `-D $POC`) for all 43. We already imported 19 as certified fixPOVs; import the remaining 24. |
| Running their tools on our C/C++ cases | Import the same inputs — this is what their harness expects natively. Nothing to generate. |
| Our pipeline on Java | **Generate** — the exploiter already does, and there is no external source. |
| LoopRepair on our Java cases | Feed it the exploiter's POVs. |

Importing rather than re-deriving also removes a real failure mode we are already paying for: two of
the ten C/C++ `hardening` rejections were **"exploiter did not produce a reproducing POV within 3
attempts"** (CVE-2016-1833, CVE-2016-10092) — we were burning agent turns rediscovering crash inputs
that ship with the benchmark. Seeding them turns those into scored runs.

This is what the `poc_given` profile in `../BASELINE_COMPARISON.md` §4.2 is for, with the
contamination guard noted there (stage the POV only — never the manifest or `official_fix.patch`).

## 6. Ordered consequences

1. Build the **sanitizer-equivalent alert tier** for all 43 C/C++ cases from `vulnloc-meta-data.json`
   (`crash_stack_trace` + `bug_type`). Blocks every C/C++ claim against San2Patch/PatchAgent.
2. Port **`test_func.sh`** into real `test_command`s. Blocks "repaired" meaning the same thing.
3. Import the **24 remaining VulnLoc PoCs**; add `seed_pov` / `poc_given`.
4. Re-run C/C++ on the degraded alert tier — the number that is actually comparable.
5. Then the adapters, San2Patch first.
6. Separately: **LoopRepair on our Java set**, using IRIS sink as `S_v` and exploiter POVs. This is
   the only cross-language comparison any of these three supports, and it runs on our home turf.
