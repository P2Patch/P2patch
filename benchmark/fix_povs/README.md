# fixPOVs

Curated, per-project **proof-of-concept exploits** derived from each CVE's
official advisory (GHSA/NVD) and its fix commit(s). They are a third evaluation
signal on top of the pipeline's live exploiter POV and the LLM verifier — and,
unlike those, they are **checked in, reused verbatim across every run, and
certified once against fixPOV**.

> **Authoring a set for a new CVE? Start with [`AUTHORING_NEW_CVE.md`](AUTHORING_NEW_CVE.md)** — the
> end-to-end workflow (fixPOV + residual, path + technique axes) that places
> everything below in order.

## What makes a fixPOV different

| | Exploiter POV (live) | fixPOV (this dir) |
|---|---|---|
| Author | generated per run by the exploiter agent | curated once from advisory + fix commit |
| Coverage | one representative path | **every** source-to-sink path a fix must block |
| Role in a run | regression witness **and a gate** | **evaluation metric only — never a gate** |
| Certified? | reproduces before patch (checked live) | reproduces on unpatched **and** blocked by the official fix |

## The contract

A POV command **exits `0` when the exploit reproduces** (vulnerability present)
and **non-zero when blocked**. On the pipeline-patched code we want every POV
blocked:

- exit 0 → `reproduced` ❌ the pipeline patch missed this path (recorded, **not** rejected)
- exit `error_exit_code` (default **2**) or timeout → `errored` (build/harness failure — recorded, **excluded from the score** so infra noise never counts as a block)
- any other non-zero exit → `blocked` ✅ the pipeline patch defended this path

So a POV command **must** return the reserved error code (2) for build/harness
failures — never let a compile error leak a generic non-zero exit, or it would be
miscounted as "blocked".

A run's **score = blocked / (blocked + reproduced)** — the fraction of real
exploit paths the pipeline's patch actually blocked. It is written to
`security_pipeline_runs/<run>/fix_pov/results.json` and surfaced by the
dashboard. **It never rejects a run.**

## Layout

```
fix_povs/
  README.md                 # this file
  AUTHORING_NEW_CVE.md      # START HERE: end-to-end new-CVE workflow (both families, both axes)
  GENERATING_POVS.md        # how to author a project's POVs (hand this to a coding agent)
  COMPLETENESS_CHECKLIST.md # path-completeness audit (every source-to-sink path)
  TECHNIQUE_COMPLETENESS.md # technique-completeness audit (every payload technique)
  manifest.schema.json      # the manifest contract
  _template/                # copy-me scaffold for a new project
  <project_slug>/
    manifest.json           # POV definitions + validation record
    official_fix.patch      # the official fix, as the "after" oracle for certification
    NOTES.md                # advisory links + path-coverage rationale
    povs/                   # POV sources / fixtures + a run entrypoint
```

`<project_slug>` matches the dataset slug in `dataset/project_info.csv`
(e.g. `srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2`) so a run resolves its POVs
automatically.

## Commands

```bash
# Which local project sources exist (candidates to author POVs for)
python -m security_pipeline fixpov list-projects

# Coverage / certification status across all manifests
python -m security_pipeline fixpov status

# Certify a project: reproduce on unpatched source, blocked by official_fix.patch
python -m security_pipeline fixpov validate --project <project_slug>

# Replay newly authored POVs against all existing accepted runs for the project
python -m security_pipeline fixpov replay --project <project_slug>

# Limit the replay to one or more run IDs (repeat --run as needed)
python -m security_pipeline fixpov replay --project <project_slug> --run <run_id>
```

In a pipeline run the POVs are replayed automatically as the last stage of every
profile (`fix_pov_eval`). `fixpov replay` provides the same evaluation for
patched worktrees that already exist, updating their dashboard artifacts without
rerunning any agents. Disable evaluation during a new run with
`--no-fix-pov-eval`.

See **[AUTHORING_NEW_CVE.md](AUTHORING_NEW_CVE.md)** for the full new-CVE workflow, or **GENERATING_POVS.md** to jump straight to authoring one project's set. For the beyond-upstream companion, see **[../residual_povs/README.md](../residual_povs/README.md)**.
