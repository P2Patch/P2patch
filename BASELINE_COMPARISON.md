# Baseline comparison — PatchAgent, San2Patch, LoopRepair

_How our pipeline compares against three published LLM vulnerability-repair systems, on our own
dataset. Written 2026-08-12. Harness lives in `baselines/`; companions: `PIPELINE_ANALYSIS_v3.md`,
`PIPELINE_ANALYSIS_v4.md`._

| | PatchAgent | San2Patch | LoopRepair |
|---|---|---|---|
| Venue | USENIX Sec '25 | USENIX Sec '25 | ICSE '26 (arXiv:2512.20203) |
| Local PDF | `~/Downloads/usenixsecurity25-yu-zheng.pdf` | `~/Downloads/usenixsecurity25-kim-youngjoon.pdf` | `~/Downloads/2512.20203v1.pdf` |
| Code | [cla7aye15I4nd/PatchAgent](https://github.com/cla7aye15I4nd/PatchAgent) · [OSF artifact](https://osf.io/8k2ac) | [acorn421/san2patch](https://github.com/acorn421/san2patch) + [benchmark](https://github.com/acorn421/san2patch-benchmark) | [Fino2020/LoopRepair](https://github.com/Fino2020/LoopRepair) |
| License | Apache-2.0 | MIT | **none** — run in place, never vendor |
| Input | sanitizer report + PoC + functional tests | sanitizer log + PoC + functional tests | **vulnerable function + statement** (CrashAnalysis localization) + PoV |
| Dataset | 178 vulns / 30 programs (ExtractFix + OSS-Fuzz + Huntr) | VulnLoc (39 of 43) + San2Vuln (27) | VulnLoc+ (40 of 53) |
| Success = | compiles ∧ PoC blocked ∧ functional tests pass | same, plus a separate manual expert label | **plausible** = PoVs pass (no functional gate); **correct** = manual |
| Headline | 92.13% union of 5 models; **84.83% best single** | **79.5%** (31/39) automated | **27/40 plausible, 15/40 correct** |
| Cost | $0.10–$2.15/case; $6.11 for the union | $0.48/case, 8.9 min | $0.074/case (gpt-4o-mini) |

---

## 0. TL;DR

1. **Our C/C++ subset *is* their benchmark.** `baselines/cases.json` computes it: **all 43** of our
   C/C++ cases are in LoopRepair's VulnLoc+, **37** are in the VulnLoc benchmark San2Patch ships,
   and **19** are in PatchAgent's published per-case table. This is not a coincidence — our C/C++
   data came from the same CrashRepair/VulnLoc lineage. It makes the comparison unusually clean
   and it means published per-case numbers already exist for most of our C/C++ cases.

2. **`san2patch-benchmark` solves our single biggest blocker.** All 43 of our C/C++ rows have
   `test_command = true` — a literal no-op — so our regression gate is vacuous on C/C++ and any
   "functional tests pass" claim would be free. That repo ships, per case, `config_func.sh` /
   `build_func.sh` / `test_func.sh`: a separate non-sanitizer build plus a `make check` runner with
   per-project tolerance for pre-existing failures. **Adopt those as our C/C++ test command**, used
   identically by us and by every baseline.

3. **The three baselines do not share a success criterion, and the differences are load-bearing.**
   PatchAgent and San2Patch gate on functional tests; LoopRepair does not (its "plausible" is only
   "all PoVs pass"). LoopRepair is also *given* the vulnerable function and statement. Comparing
   within a metric is mandatory; a single leaderboard across all three would be wrong.

4. **Java stays out of scope for all three.** All 117 of our recorded runs are Java, and every one
   of these systems is sanitizer-driven C/C++. ~46% of our Java CWEs (XSS, authn/authz, info
   exposure) produce no sanitizer-observable fault at all. That is a scope *result* worth
   reporting, not a comparison to attempt.

5. **The thing none of them measure about themselves — and we can.** All three validate a patch by
   "the PoC no longer crashes." PatchAgent's §8 concedes this may pass patches that don't truly
   mitigate; San2Patch's manual-vs-automated columns disagree often for the same reason.
   `PIPELINE_ANALYSIS_v4.md` measured exactly that failure at 25% on our alert-only arm. **Running
   their patches through our fixPOV and residual POV harnesses is the most interesting
   experiment in this whole plan**, and it is cheap once the adapters exist.

---

## 1. What each system does

### 1.1 PatchAgent — LSP + patch verifier + four interaction optimizations

Input is a crash you already have: a sanitizer report (ASan/MSan/UBSan/TSan/Jazzer), the crashing
input, and a functional test suite. Static analysis reports are explicitly *not* used.

One LLM agent given three abilities it lacks natively: `viewcode(file, range)` and
`find_definition(sym, row, col)` over LSP (clangd for C/C++), and `validate(patch)` — a verifier
that applies, compiles, replays the PoC under the sanitizer, then runs functional tests. Temporal
bugs additionally get **LeakSanitizer**, because LLMs "fix" a UAF by deleting the `free()`, which
silences ASan while leaking. Agent is reset each round; temperature 1; up to 15 iterations.

The contribution is four middleware optimizations (§5), motivated by observed gaps against a human
expert:

- **Report Purification** — parse the raw report: strip addresses/shadow bytes, recompute access
  offsets and object sizes, annotate types, append repair suggestions.
- **Chain Compression** — execute trivial inference steps without the LLM. *Dominator Action*
  (auto-run the follow-ups a `find_definition` needs to be complete) and *Heuristic Exploration*
  (auto-explore symbols near lines named in the report). A 4-round chain collapses to 1.
- **Auto Correction** — repair the LLM's malformed action arguments rather than bouncing them:
  widen too-narrow ranges, resolve row/col by scanning recent snippets in reverse, and **fix
  multi-hunk patch line numbers and context by minimal edit distance** so a nearly-right patch applies.
- **Counterexample Feedback** — accumulate failed patches and feed them back as "don't do this
  again", because temperature alone doesn't diversify attempts.

**Ablation (GPT-4o, 75 cases): full 77.33% → no AC 38.67% → no CC 62.67% → no RP 64.00% → no CF
70.67%.** Auto Correction carries it, largely because without it the model can't emit correctly
formatted patch hunks. That is a finding about scaffolding, not reasoning — and Claude Code's tool
layer already absorbs most of AC's job, which is a real confound when we compare.

Failure mass: 33,336 incorrect patches — 45.0% syntax, 49.2% failed security test, 5.8% failed
functional test. Time: 28.7–45 min/case, **74–82% of it inside `validate`**.

> **Read the 92.13% correctly.** It is a *union over five models* ("in the worst scenario… we would
> need to run each case through all models, which would cost $6.11", §7.5). The comparable
> single-system number is **84.83%** (Claude-3 Opus). Comparing our single-model result to their
> union would be a straw man in our favour.

### 1.2 San2Patch — sanitizer log → Tree-of-Thought → validated patch

Closest in spirit to a "pure prompting" system: **sanitizer log and source code only**, no program
analysis, no developer input. Four-stage pipeline, each a distinct prompt invocation:

1. **Vulnerability Comprehension** (CoT + Self-Consistency, K=3) — infer root cause, type, impact
   from the log alone.
2. **Where-To-Fix** (ToT, K=5/N=3) — fault localization from the crash stack trace.
3. **How-To-Fix** (ToT, K=3/N=1) — formulate a repair strategy *before* writing code, explicitly to
   avoid defaulting to training-data patterns.
4. **Candidate Generation** — generate **fully modified files, not diffs**, then derive the patch
   with a diff tool. Neat trick: it sidesteps the line-numbering failure that PatchAgent needs Auto
   Correction to repair.

Context comes from an **AST-based retriever** (Algorithm 1): walk up to M=5 compound statements
enclosing the target line to get a syntactically meaningful block of 20–100 lines, plus
function-level signature/return info. Deliberately *narrow* — they report that program slicing and
inter-procedural context made fault localization **worse**.

Validation: build → PoC replay → project unit tests. Every patch that passed automated tests was
**also reviewed by two security experts** (third for disagreements) into four labels: correct
(developer-matched), correct (alternative), incorrect (some tests), incorrect (all tests).

Results: **79.5% (31/39)** on VulnLoc vs ExtractFix 43% and VulnFix 51%; **63% (17/27)** on their
new San2Vuln set (recent/unseen vulns, 6 of them with no official fix yet). Buffer overflows
18/22 (81.8%). $0.48/case, 8.9 min. Model-sensitive: GPT-4o 31/39, Claude-3.5-Sonnet 28,
Gemini-1.5-Pro 18, GPT-3.5-turbo 8.

Notable admissions: **UAF 0/2**, and the functional-correctness rate among vuln-fixing patches is
only **30%** for San2Patch and **48%** for its own No-Context variant (Table 4) — i.e. most patches
that stop the crash break something. §5.1 states the scope limit plainly: *"vulnerabilities that
cannot be detected by any sanitizer are fundamentally unpatchable"* by this design.

### 1.3 LoopRepair — location-aware generation + taint-guided patch selection

Different problem statement: **function-level AVR**. It is *given* the vulnerable function `F_v` and
vulnerable statement `S_v` (from CrashAnalysis, CrashRepair's localizer) and outputs a patched
function. Two ideas:

- **Patch hunk location prediction** — the observation that *the vulnerable hunk is not where you
  patch*. It predicts the line-number sequence that needs editing before generating any code,
  framed as a translation task with few-shot CoT examples drawn from Big-Vul. Motivated by 77.5% of
  VulnLoc+ being multi-hunk.
- **Taint trace-guided patch selection** — when every candidate fails the PoV, pick which failing
  patch to iterate on. Discard any patch that changes the taint sink or the CWE type (that's a *new*
  vulnerability, not progress), then rank survivors by **taint statement coverage**. Higher coverage
  = the patch forced the exploit through more statements = closer to blocking it. They tested
  branch coverage, AST difference and cosine similarity as alternatives; only taint statement
  coverage produced patches in later iterations at all (23/27 of their fixes add an `if`-block, and
  branch coverage can't see an unexecuted branch).

Results: **27/40 plausible, 15/40 correct** at 3 iterations (from 19/9 at 1 iteration). Beats
CrashRepair (27 plausible but only 5 correct — mutation produces many plausible-but-wrong patches),
VulnFix (24/5), ChatRepair (14/6), ThinkRepair (19/5), ITER (12/3). Ablation: without hunk-location
prediction 24/13, without taint ranking 19/7, without both 11/3.

**Localization dominates everything else:** of 22 cases with correct function-level localization,
19 got correct hunk predictions → 12 correct patches; of the 21 with wrong hunk locations, 3.

Cost: $0.074/case on gpt-4o-mini; median 14.5 min. Claude-3.5-Sonnet did *worse* (9 plausible) at
73× the cost — they attribute it to divide-by-zero cases.

> **Its metric is the weakest of the three.** "Plausible" has no functional-test gate at all. A
> LoopRepair number and a PatchAgent number are not the same measurement and must never be pooled.

---

## 2. Where we actually meet — measured

`baselines/cases.json`, generated by `baselines/common/build_case_map.py`:

| | count |
|---|---|
| C/C++ cases in our dataset | **43** |
| …with a curated alert | 41 |
| …with a **certified** fixPOV | 19 |
| …with a real functional test command | **0** (all `test_command = true`) |
| …in LoopRepair's VulnLoc+ | **43 / 43** |
| …in the VulnLoc benchmark (San2Patch) | 37 |
| …in PatchAgent's Table 2 | 19 |
| Java cases | 213 (all 117 recorded runs; **0** C/C++ runs so far) |

Our six C/C++ cases outside VulnLoc — jasper CVE-2020-27828 / CVE-2021-3272, libtiff CVE-2018-18557 /
CVE-2022-4645 / CVE-2022-48281, libxml2 CVE-2016-1833 — are **exactly** LoopRepair's "RED-TEAM"
CrashRepair additions. The provenance is the same all the way down.

Our C/C++ POVs already have the shape all three consume: an ASan build (`-fsanitize=address` in the
Dockerfile) plus a crashing input (e.g. `fix_povs/git__binutils-gdb_CVE-2017-6965_.../povs/1.bin`,
from CrashRepair/VulnLoc+) with an exit-code oracle grepping the sanitizer's `ERROR:` line.

### 2.1 The 19-case overlap with PatchAgent's Table 2

Transcribed in `baselines/paper_reported/patchagent_table2.json`. On the 19 shared cases:
**PatchAgent ● 19/19, ExtractFix ● 11/19, Zero-Shot ● 9/19 (7 n/a).** Nine of their 28 are absent
from our dataset (binutils CVE-2018-10372; coreutils gnubug-25003, bugzilla-26545; jasper
CVE-2016-9387; libtiff CVE-2016-9273, CVE-2016-10094, CVE-2014-8128, CVE-2016-3623; libxml2
CVE-2016-1834) — all ExtractFix cases with public PoCs, cheap to backfill for a 28/28 overlap.

### 2.2 Why Java is out of scope

The PatchAgent fork supports Java via Jazzer, so this is not a flat no — but the ceiling is low.
Its Java path expects an **OSS-Fuzz project + Jazzer harness** (`OSSFuzzPoC(poc.bin, "HamcrestFuzzer")`);
none of our Java CVEs are OSS-Fuzz projects and none have harnesses. More fundamentally, the input
is a *sanitizer report*, and most of our Java CVEs don't crash. Mapping our Java CWEs onto Jazzer's
detectors (path traversal, OS command injection, deserialization RCE, SQLi/LDAP/XPath, SSRF, regex
injection): **~116/213 (54%) plausibly mappable, ~97 (46%) not** — XSS (38 rows) has no detector,
because XSS is not an in-process fault. Of our 117 actual runs, 106 are mappable in principle but
all 11 CWE-079 runs are not.

Authoring ~100 Jazzer harnesses to still exclude 46% by construction is not a good trade. Report it
as scope: *"these designs are inapplicable to 46% of our benchmark because those vulnerability
classes produce no sanitizer-observable fault."* San2Patch says the same thing about itself (§5.1).

---

## 3. The five asymmetries to control

| # | Asymmetry | Why it biases | Neutralization |
|---|---|---|---|
| **A** | **Input.** PatchAgent/San2Patch get a PoC + sanitizer report; LoopRepair additionally gets the vulnerable function *and* statement. We get a static alert and `full` manufactures its own PoC. | Uncontrolled, the comparison measures information regime, not repair skill. | Run **two configurations** — §4.2. Note LoopRepair sits on an easier rung than the other two; say so rather than averaging it away. |
| **B** | **Metric.** Ours adds an LLM verifier gate they don't have; LoopRepair drops the functional gate they do have. | Both directions. | Headline = compile ∧ PoC blocked ∧ functional tests pass, computed identically for everyone. Report our verifier verdict and LoopRepair's plausible/correct split *separately*. |
| **C** | **Budget & model.** 15 iterations (PatchAgent), 3×5 candidates (LoopRepair), 5-model union for the 92.13%; models are 2024-era. Ours: 1 run, ≤3 corrections, Sonnet-5/Opus-4.8. | Large, both ways. | Single-model to single-model. Re-run each baseline on a **current** model so model era isn't the explanation. Report matched and native budgets. |
| **D** | **Functional tests.** Our C/C++ `test_command` is `true`; PatchAgent's `Builder.function_test()` also defaults to a no-op; LoopRepair has no functional gate. | Without real tests everyone gets free credit for functionality-destroying patches — and San2Patch's Table 4 says only 30% of its vuln-fixing patches preserve functionality, so this is not hypothetical. | **Adopt `san2patch-benchmark`'s `test_func.sh` per case**, for us and every baseline. Exclude their 7 no-functional-test cases from both denominators. |
| **E** | **PoC provenance.** Our C/C++ PoCs, VulnLoc, ExtractFix and CrashRepair are one lineage. | Good for comparability, bad for independence. | State it. Where it matters, score with our *fixPOVs* (advisory-derived, not PoC-derived) rather than the benchmark's crash input. |

---

## 4. Comparison protocol

### 4.0 Tier 0 — paper cross-reference (zero compute)

Put our results beside the published per-case marks in `baselines/paper_reported/`. Free once T1
runs. **Context, not the claim** — different harnesses, different functional tests, different model
eras. Never pool a `✔` from a paper with a `repaired` we measured.

### 4.1 Tier 1 — our pipeline on the C/C++ subset (prerequisite for everything)

Target the 41 C/C++ cases with alerts; the 19 with certified fixPOVs are the core.

1. **Real functional tests.** Port `san2patch-benchmark`'s `config_func.sh`/`build_func.sh`/
   `test_func.sh` into our `build_info.csv` `test_command` (and, where needed, a separate
   non-sanitizer build). Six of our 43 aren't in VulnLoc and need hand-authored equivalents; seven
   of theirs have no usable suite and must be excluded from both sides' denominators.
2. **Verify the regression gate on C/C++.** `regression_diff` already documents the no-JUnit-XML
   path (genuine iff the baseline replay exits 0 and the patched one doesn't). Confirm on one
   project before batching.
3. **`agent_guard` coverage.** The `clean` rule matches `mvn|gradle` only; C/C++ agents will reach
   for `make clean`. One-line regex fix.
4. Batch `python -m security_pipeline run --all --profile <arm> --jobs 4` over the C/C++ alerts.

### 4.2 The two configurations

**Config 1 — equal input (patcher vs patcher).** Everyone gets the same crashing PoC and sanitizer
report. Needs a new profile — add a row to `PROFILES` + `PROFILE_PATCHER_EVIDENCE` in `stages.py`,
no orchestrator changes:

```python
"poc_given": (
    "worktree", "docker_build", "seed_pov", "patcher", "converge", "verifier",
    "fix_pov_eval", "residual_eval",
),
```

with a new `SeedPovStage` staging the case's certified POV instead of invoking the exploiter, and
`patcher_evidence = "full"`.

> ⚠️ **Contamination guard.** fixPOVs live beside `official_fix.patch`, and the whole
> `fix_pov_eval` design keeps agents from ever seeing them. Seeding must stage **only** the POV
> sources — never the manifest, fix summary, or fix patch — and `fix_pov_eval` on a `poc_given`
> run is then no longer independent of the patcher's input. Score those runs on the **residual**
> POVs and on fixPOVs *other than* the seeded one, and say so.

**Config 2 — equal task (end-to-end).** Ours gets only the static alert and must find its own
reproducer (`full` / `baseline_eval`); the baselines get the PoC they require. Not unfair to them —
it is the honest statement that *our system does not require a reproducer and theirs do*. Report as:
"under their input assumption both reach X%/Y%; under ours, they are inapplicable to N cases."

Arms: `baseline`, `full`, `baseline_eval`, `poc_given`. `baseline_eval` is still the arm v4 predicted
is best and has still never been run.

### 4.3 Tier 2 — run the baselines

All three go through `baselines/` (see its README). Integration difficulty, easiest first:

- **San2Patch — easiest, do first.** Artifact-evaluated, MIT, and its benchmark already contains
  our cases with build/test/PoC scripts. Mostly a matter of running `scripts/run_dataset.py` over
  the VulnLoc set and normalizing output. Also gives us the functional tests from item 4.1.1.
- **PatchAgent — tractable.** `patchagent/builder/builder.py` is a clean ABC; a custom builder needs
  `language`, `language_server` (reuse their clangd wrapper), `build(patch)`, `replay(poc, patch)`
  → their `SanitizerReport` parser, and `function_test(patch)` — **which must be implemented; it
  defaults to a silent no-op.** ~150–250 lines driving our existing per-CVE Docker images. Note
  their `check_patch`/`format_patch` do `git reset --hard && git clean -fdx` per attempt, i.e. a
  cold rebuild per iteration — consistent with `validate` being 74–82% of their wall time, and the
  opposite of our no-`clean` discipline. 15 iterations × cold build on binutils is hours per case;
  consider a symmetric budget cut.
- **LoopRepair — hardest to compare, not hardest to run.** It needs CrashAnalysis localization
  output per case, and its metric has no functional gate. Simplest honest treatment: run it, then
  score its patches with *our* functional tests and POV harnesses, and report both its native
  "plausible/correct" and our stricter numbers. No license file — run in place from `vendor/`, never
  copy.

For each: **reproduce 2–3 cases the paper reports before trusting any number.** If their own cases
don't reproduce, the adapter is wrong, not the tool.

### 4.4 Metrics to produce

| Metric | Ours | Baselines | Notes |
|---|---|---|---|
| **compile ∧ PoC blocked ∧ functional tests pass** | derivable from `state.json` | native (LoopRepair: we add the functional gate) | **the headline, apples-to-apples** |
| fixPOV score (real CVE exploit blocked) | `fix_pov/results.json` | score their patch with the same harness | **the interesting one — none of them measure this** |
| Residual POV score (beat the official fix) | `residual/results.json` | same | bonus metric; 0 is a fine result |
| Blind LLM patch-quality judge | `dashboard/backend/analysis/` | same rubric, arm-anonymised | separate; v4 showed it is inverted on the case that matters most |
| Manual correct/alternative/incorrect | — | San2Patch's 4-label taxonomy | worth adopting for our own patches too |
| Diff size / blast radius | `git/patch_only.diff` | computed | none of them report it |
| Cost per successful repair | `totals.cost_usd` | all three report $ | directly comparable |
| **Applicability** (cases the system can accept) | 256/256 | 43 C/C++ (+ ~116 Java with hand-authored harnesses) | the §2.2 scope result |

The row that matters most: **replay our fixPOV and residual POVs against their patches.**
PatchAgent §8 concedes their validation may pass patches that don't mitigate; San2Patch's manual
review disagrees with its automated verdict often enough to have its own column; LoopRepair has no
functional gate at all. If their ✅-by-their-metric patches fail our fixPOVs at a non-trivial rate,
that is the evaluation gap they themselves flagged as future work — a genuine contribution, not a
cheap shot.

---

## 5. Ordered work plan

| # | Item | Blocks | Effort |
|---|---|---|---|
| 1 | `./baselines/setup.sh`; regenerate `cases.json` from the cloned VulnLoc metadata | everything | XS |
| 2 | Port `test_func.sh`/`build_func.sh` into real C/C++ `test_command`s; record the 7 with no suite | everything | M |
| 3 | Smoke-test our pipeline on 2–3 C/C++ cases (`full`); verify the regression gate | T1 | S |
| 4 | `agent_guard`: extend the `clean` rule to `make` | T1 | XS |
| 5 | T1 batch: `baseline`, `full`, `baseline_eval` over the 41 C/C++ alerts | T0 | L (compute) |
| 6 | T0 writeup: our results vs `paper_reported/` | — | S |
| 7 | `SeedPovStage` + `poc_given` profile (with the contamination guard) | Config 1 | M |
| 8 | San2Patch adapter + reproduce 2–3 of their cases | T2 | M |
| 9 | PatchAgent `P2PatchBuilder` + `P2PatchPoC` | T2 | M–L |
| 10 | LoopRepair adapter (CrashAnalysis localization input) | T2 | L |
| 11 | Score **all** baseline patches with our GT + residual POV harnesses and blind judge | the interesting result | M |
| 12 | Fill `looprepair_table2.json` per-case from their repo (not the PDF) | T0 completeness | S |
| 13 | Backfill PatchAgent's 9 missing Table-2 cases into our dataset (28/28 overlap) | optional | M |

Items 1–6 stand on their own — we need C/C++ coverage regardless. Start there even if the adapters slip.

---

## 6. Threats to validity to declare

- **Shared benchmark lineage.** Our C/C++ subset, VulnLoc, VulnLoc+, ExtractFix and CrashRepair are
  one family. Excellent for comparability, poor for independence. Where independence matters, score
  with advisory-derived fixPOVs, not the benchmark's crash input.
- **Different functional test suites.** Mitigated by item 2 (one suite for everyone), but T0's
  paper-reported marks were measured under the authors' own suites. Label them as such.
- **Model era.** All three were evaluated on 2024/2025 models; ours are two generations newer. Run
  each baseline on a current model before attributing any gap to design.
- **Budget.** 15 iterations vs 3×5 candidates vs our 1 run × ≤3 corrections. Report both matched and
  native.
- **Fork vs artifact.** PatchAgent's GitHub repo is an evolved production fork; the paper's numbers
  belong to the OSF artifact. `baselines/pins.json` records what we ran — disclose it.
- **Transcription.** `paper_reported/` was read off PDF tables with small glyphs. `san2patch_table1.json`
  is marked medium confidence and LoopRepair's per-case table is deliberately **not** transcribed.
  Verify any row in the source before publishing a number off it.
- **Contamination.** Our fixPOVs sit beside `official_fix.patch`. Anything staging a POV into an
  agent-visible tree needs the §4.2 guard.

---

## Sources

- [PatchAgent (USENIX Sec '25)](https://www.usenix.org/system/files/usenixsecurity25-yu-zheng.pdf) · [code](https://github.com/cla7aye15I4nd/PatchAgent) · [artifact](https://osf.io/8k2ac)
- [San2Patch (USENIX Sec '25)](https://www.usenix.org/system/files/usenixsecurity25-kim-youngjoon.pdf) · [code](https://github.com/acorn421/san2patch) · [benchmark](https://github.com/acorn421/san2patch-benchmark)
- [LoopRepair (ICSE '26, arXiv:2512.20203)](https://arxiv.org/abs/2512.20203) · [code](https://github.com/Fino2020/LoopRepair)
