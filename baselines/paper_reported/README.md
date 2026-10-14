# Paper-reported results (transcribed)

Per-case results **as published**, transcribed by hand from each paper's tables. These are the
zero-compute comparison point: for any case in the intersection with our dataset, we can put our
result beside the number the authors themselves reported, before running anything.

**These are not measurements we made.** Treat every number here as a claim by its authors,
evaluated under *their* harness, *their* functional tests, and *their* models. A `✔` here and a
`repaired` in `../results/` are not the same evidence and must never be pooled into one figure.
Use them side by side, labelled.

| file | source | cases | metric |
|---|---|---|---|
| `patchagent_table2.json` | PatchAgent Table 2 (p. 4391) | 28 (ExtractFix subset) | ● fixed + functional tests pass · ◐ fixed but broke functional tests · ○ failed · `/` n/a |
| `san2patch_table1.json` | San2Patch Table 1 (p. 4410) | 39 (VulnLoc) | automated (A) = vuln + functional tests passed; manual (M) = expert label |
| `looprepair_table2.json` | LoopRepair Table 2 (arXiv:2512.20203, p. 7) | 40 (VulnLoc+) | plausible = passes all PoVs · correct = manually judged equivalent to developer fix |

## Reading them together

The three papers do **not** share a success criterion, and the differences are load-bearing:

- **PatchAgent** and **San2Patch** both gate on functional tests. **LoopRepair does not** — its
  "plausible" only means all PoVs pass, which is a strictly weaker bar, and its "correct" is a
  human judgement against the developer patch rather than a test outcome.
- **San2Patch** additionally reports a manual expert label (`M`) separate from the automated
  verdict (`A`), and they disagree often — that gap is itself a finding about automated patch
  validation, and it is the same gap `PIPELINE_ANALYSIS_v4.md` measured on our side.
- **LoopRepair** is given the vulnerable function *and* statement as input (function-level AVR
  with CrashAnalysis localization). PatchAgent and San2Patch localize from the sanitizer report
  themselves. Ours localizes from a static alert. Three different information regimes.

So: compare within a metric, never across. `../common/build_case_map.py` emits the join.

## Transcription integrity

Transcribed from the PDFs on 2026-08-12. Small-glyph tables (LoopRepair Table 2 especially) are
error-prone to read; `looprepair_table2.json` carries `"transcription_confidence"` per project and
the low-confidence rows must be re-checked against the authors' repo before anything is published
off them. If a number matters, verify it in the source PDF — these files are a convenience index,
not the citation.
