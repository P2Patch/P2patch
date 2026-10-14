# Analysis Agents (Phase 2) — Research-Grounded Spec

Four on-demand agents layer evaluation on top of each run. They follow the same
pattern as the pipeline's exploiter/patcher/verifier (Claude Code CLI + a system
prompt + a JSON schema), and cache results to
`security_pipeline_runs/<run>/analysis/<agent>/` so they're browsable and only
recomputed on request.

Feasibility is confirmed against the existing data: every run maps to its CVE via
the finding-id hash, `dataset/fix_info.csv` gives the exact file/class/method/
line of every official fix, and GitHub `.diff` + NVD are reachable.

```
analysis/
  ground_truth/    cve.json, official_exploit.json, reference_patch.json, fix/*.diff
  patch_eval/      scorecard.json
  exploit_eval/    scorecard.json
```

Design rule from the research: **gate on execution/deterministic signals, score
the reasoning-heavy dimensions with a reference-anchored, evidence-citing,
ensembled LLM judge, and treat similarity metrics as _evidence to the judge_,
never as the verdict.**

---

## 1. CVE Research Agent

Fetches canonical CVE metadata and locates an official/public exploit if one
exists. Deterministic fetchers first; LLM only to judge candidate genuineness.

**Fetch pipeline** (mostly keyless; only GitHub needs a free `GITHUB_TOKEN`):

- **Phase A — metadata (parallel):** `cveawg.mitre.org/api/cve/{CVE}` (authoritative
  description/CWE/refs) · NVD `services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE}`
  (CVSS + `Patch`/`Exploit`-tagged refs) · OSV `api.osv.dev/v1/vulns/{GHSA}`
  (affected/fixed ranges, GIT fix events) · GHSA `api.github.com/advisories/{GHSA}`.
  Merge; extract fix commits from `Patch`-tagged refs + OSV GIT `fixed` events.
- **Phase B — exploitation signal:** CISA KEV feed (filter `cveID`); NVD `Exploit` refs.
- **Phase C — locate exploit (curated → aggregated, stop-early):** Metasploit
  `modules_metadata_base.json` → Exploit-DB `files_exploits.csv` → Nuclei
  `http/cves/{YEAR}/{CVE}.yaml` → nomi-sec `PoC-in-GitHub/{YEAR}/{CVE}.json` →
  trickest `cve/{YEAR}/{CVE}.md` → (fallback) GitHub code/repo search.
- **Phase D — LLM genuineness judge** for aggregated candidates: require exact
  CVE-token match **and** (product/package match **or** vuln-class + affected-version
  match) **and** real exploit-code substance. Reject changelog/lockfile mentions,
  bulk-scanner listings, the patched project itself, product/platform mismatches.
  Output confidence + evidence lines. Rank Metasploit > Exploit-DB > Nuclei >
  top-star validated repo.

Rate-limit gotchas: NVD keyless = 5 req/30s (key → 50); GitHub REST advisories
60/hr unauth (5000 with PAT), GraphQL + code search require a token. Cache the
big blobs (Metasploit index, KEV, Exploit-DB CSV) locally.

---

## 2. Reference-Patch Agent

Produces the ground-truth fix to compare against. Deterministic core + one LLM
summarization step.

- Deterministic: read `fix_info.csv` localization (file/class/method/lines) for
  the CVE; fetch each fix-commit `.diff` from GitHub; slice the changed hunks in
  the production (non-test) files.
- LLM: emit a **root-cause statement**, a **requirements checklist** a valid fix
  must satisfy, and the **relevant reference code**. This output becomes the
  "golden rubric" that anchors the Patch Evaluation judge (this anchoring is what
  makes the judge reliable — HITL patch-eval work).

---

## 3. Patch Evaluation Agent

Scores our `patch_only.diff` against the reference fix. Layered pipeline.

- **Layer 1 — deterministic similarity (evidence only):** normalized exact match,
  AST/token similarity + CodeBLEU, and **structural overlap** (do we edit the same
  file/method/sink as the official fix — the single most predictive cheap signal).
  High similarity = weak positive evidence; low similarity is **not** negative
  evidence (a correct rewrite at a different valid location scores low).
- **Layer 2 — execution grounding (authoritative):** POV fails post-patch /
  succeeded pre-patch (reuse the run's `pov_before`/`pov_after`); regression
  tests pass; (Phase 4) static-analyzer residual-CWE scan.
- **Layer 3 — reference-anchored LLM judge** over: CWE + description, the
  vulnerable sink, POV + exec results, **our diff + the official diff**, Layer-1
  signals, and the Reference-Patch golden rubric.

**Rubric — 8 dimensions, 1–5** (hard gates: 1 · Vulnerability Elimination and
5 · No Regressions):

1. **Vulnerability Elimination** — CWE actually gone (not just the observed payload).
2. **Root-Cause vs Symptom** — fixes the flaw at the sink/trust boundary, not the caller.
3. **Completeness / Variant Coverage** — all tainted paths + bypass variants (encodings, `..`, null byte, case).
4. **Developer-Intent Alignment** — same defensive strategy/location as, or a superset of, the official fix.
5. **Functional Correctness / No Regressions** — legitimate behavior preserved.
6. **No New Vulnerabilities/Defects** — no TOCTOU/ReDoS/new injection/crash.
7. **Minimality & Localization** — tight diff at the right place.
8. **Mitigation-Technique Soundness (CWE-specific)** — uses the defense-of-record:
   - CWE-022: canonicalize → verify inside base dir (resolve symlinks first). Blocklisting `../` = weak.
   - CWE-078: no shell — `ProcessBuilder` arg array + allowlist. Escaping metacharacters = weak.
   - CWE-079: context-aware output encoding at the sink / auto-escaping template.
   - CWE-094: eliminate dynamic eval of untrusted input; safe parser / allowlist.

Judge must emit per-dimension score + 1-line rationale + **cited changed-line
evidence**, plus a semantic-equivalence verdict vs reference ∈ {equivalent /
superset-stronger / subset-weaker / different-valid / different-wrong}. Bias
controls: anonymize which diff is ours, randomize order, ensemble ≥3 samples,
flag high-variance for review.

---

## 4. Exploitation Analysis Agent

Scores our POV and, when an official exploit exists, compares to it.

**Oracle (the core fix for the 71.5% naive false-positive rate):** conjunctive +
differential — `SinkHit ∧ canary-impact ∧ (both vanish on the patched build)`.
Phase 2 approximates SinkHit via a stack-trace assertion + LLM reasoning over the
POV/logs/trace; Phase 4 adds real AspectJ sink instrumentation + mutation-based
oracle-strength checks.

**Rubric — 8 dimensions, 1–5** (hard gates: 1 · Discriminative Power and
2 · Sink Coverage):

1. **Discriminative Power** — passes on vulnerable, fails on patched, and fails _because of_ the fix.
2. **Sink Coverage** — dynamically reaches the exact sink from the finder trace with tainted data.
3. **Specificity** — triggered by the root-cause defect, not a generic exception / trivial assertion.
4. **Impact Demonstrated** — a distinctive canary side effect (file written outside base dir; attacker command side-effect; sentinel code exec; unencoded script in an executable context), not merely "sink reached".
5. **Fidelity / Realism** — real public API + realistic input channel; no hardcoding, simulation, or private-hook shortcuts.
6. **Reproducibility / Determinism** — stable across repeats in a pinned container.
7. **Minimality** — 1-minimal reproducer, single decisive assertion.
8. **Oracle Robustness (anti-cheat)** — success can't be met by swallowed exceptions or an unconditional marker.

**Compare to official exploit** on three axes — same sink (trace overlap), same
attack vector, same impact — plus discriminative parity, yielding a verdict ∈
{Weaker, Equivalent, **Stronger**} (a generated POV can be stronger: multiple
variants + a proper patched-build negative control). Also bucket both on the
CVSS Exploit-Code-Maturity scale (Unproven → PoC → Functional → High).

---

## Key sources

Patch eval: Invalidator (TSE'23), ODS (TSE'21), VulnRepairEval (2025), PatchEval
(2025), Incomplete-Patches taxonomy (2025), HITL LLM-as-judge patch eval (2025),
CodeBLEU (2020), CISA CWE-078 secure-by-design, MITRE/OWASP per-CWE guidance.
Exploit eval: PoC-Gym / CWE-Bench-Java (the naive-oracle 71.5% FP result +
SinkHit definition), PoCGen (per-CWE canary checkers), VulScope (PoC migration /
equivalence), Igor + AURORA (root-cause clustering), ddmin (minimality), CVSS
Exploit-Code-Maturity, OWASP WSTG XSS oracle.
CVE sources: cveawg, NVD API 2.0, OSV.dev, GitHub advisories (REST/GraphQL/OSV
export), CISA KEV, Metasploit, Exploit-DB, Nuclei, nomi-sec/PoC-in-GitHub,
trickest/cve.
