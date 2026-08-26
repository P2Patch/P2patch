# P2Patch Lab

An observability, evaluation, and control dashboard for the `security_pipeline`
(exploit → patch → verify). It reads the pipeline's on-disk run artifacts, maps
each redacted run back to its real CVE and official fix, and (in later phases)
runs analysis agents that score the generated patch and POV against ground truth.

## Architecture

```
dashboard/
  backend/     FastAPI — reads security_pipeline_runs/, reuses the pipeline
               package for finding-id/metadata, resolves ground truth from
               dataset/*.csv, fetches official fix diffs from GitHub.
  frontend/    Vite + React + TypeScript + Tailwind SPA.
```

The backend never mutates run artifacts. Analysis-agent results (Phase 2) are
cached under `security_pipeline_runs/<run>/analysis/` so they are browsable and
recomputed only on demand.

## Run it

### Development (hot reload, two processes)

```bash
# 1. backend — from dashboard/backend
python3 -m venv ../../.venv && source ../../.venv/bin/activate   # or reuse the repo venv
pip install -r requirements.txt
uvicorn app:app --reload --port 8000

# 2. frontend — from dashboard/frontend
npm install
npm run dev          # http://localhost:5173  (proxies /api -> :8000)
```

### Single process (backend serves the built UI)

```bash
cd dashboard/frontend && npm install && npm run build
cd ../backend && source ../../.venv/bin/activate && pip install -r requirements.txt
uvicorn app:app --port 8000        # open http://localhost:8000
```

Or use the helper: `./dashboard/dev.sh` (build UI + serve on :8000).

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/stats` | Aggregate KPIs (accept rate, by-CWE, spend) |
| GET | `/api/runs` | Run summaries |
| GET | `/api/runs/{id}` | Full run detail (stages, agents, commands, trace, ground truth). Carries `profile`, `model`, and a profile-filtered stage rail |
| GET | `/api/runs/{id}/agents/{name}` | Agent input.md / output.json / stderr / metadata |
| GET | `/api/runs/{id}/diff/{full\|patch_only\|pov}` | Our diffs |
| GET | `/api/runs/{id}/log/{name}.log` | Docker command logs |
| GET | `/api/runs/{id}/ground-truth?diffs=true` | CVE mapping, fix localization, official fix diffs |
| GET | `/api/runs/{id}/fix-pov-replay` | fixPOV replay availability, progress, and latest result |
| POST | `/api/runs/{id}/fix-pov-replay` | Replay the current curated fixPOVs against the preserved patched worktree |
| GET | `/api/runs/{id}/retrofit` | Retrofit availability + background-job status |
| POST | `/api/runs/{id}/retrofit` | Run the verifier against this run's existing patch (assess-only) |
| POST | `/api/runs/{id}/stop` | Stop the live run that produced this run dir |
| DELETE | `/api/runs/{id}` | Delete a run directory (path-validated; refuses an active run) |
| GET | `/api/live/options` | Selectable experiment profiles, efforts, and models for the launcher |
| GET | `/api/live/targets` | Launchable findings (CVE/CWE, source availability, per-profile prior runs) |
| POST | `/api/live/launch` | Spawn a single pipeline run for one alert; returns a launch handle |
| POST | `/api/live/batch` | Queue a batch of runs; a scheduler starts them up to `concurrency` |
| GET | `/api/live/{launch_id}/stream` | Server-Sent-Events: log + stage snapshots until terminal |
| GET | `/api/live/{launch_id}` | Point-in-time snapshot (non-streaming) |
| POST | `/api/live/{launch_id}/stop` | Stop a queued or running launch |
| GET | `/api/live/launches` | Launch queue / history with live state (queued/running/done) |

The two evaluation endpoints (`analysis/patch-eval`, `analysis/exploit-eval`)
take an optional `?samples=N` (1–5). `samples>1` is **ensemble judging**: the
judge runs N times in parallel and the result carries an `ensemble` block with
the median score, per-dimension spread, band/gate agreement, and a confidence
tier. `samples=1` (default) is the legacy single-shot path.

Dry runs (`dry_run` verdict — context/metadata only, no Docker/Claude) are
launchable for plumbing checks but excluded from the experiment list and stats.

## Experiment controls

The Live and Experiments pages drive the pipeline's experiment profiles and run
management:

- **Profile + model selectors** on the launcher (`GET /api/live/options`). Run
  `full`, `baseline` (alert-only), `baseline_eval` (controlled A/B), or
  `no_verifier`, on a chosen model. The workflow rail on the live/detail views
  reflects the selected profile's stages — a `baseline` run shows only
  worktree → docker_build → patcher, not the phantom exploiter/verifier stages.
- **Retry budgets** on the launcher — how many times a failing objective check
  is handed back to the agent that owns it before the run is rejected: patch
  attempts per gate (POV-after, regressions, each hardening round) and exploit
  attempts (a POV that did not reproduce). Both default to 3; `1` restores the
  old one-shot gates. Retries appear as a **Self-correction** panel on the live
  and run-detail views (`retries` in the run payload) — what failed and which
  attempt answered it — and the live rail keeps showing the retrying agent
  instead of looking stalled while it works.
- **Batch runs with concurrency** — multi-select findings on the Live page and
  queue them (`POST /api/live/batch`). An in-process scheduler keeps at most
  *N* running at once (default 1, chosen per batch) and starts the next as each
  finishes. The launch-queue panel polls state (queued/running/done) and can
  stop items.
- **Stop / delete** — stop a queued or running launch, or delete a run
  directory from the Experiments table (`POST /api/runs/{id}/stop`,
  `DELETE /api/runs/{id}`; delete is a two-step inline confirm and refuses an
  active run).
- **Share run artifacts** — download one run from its detail page or Experiments
  row (`GET /api/runs/{id}/export`), or select several runs/projects and use
  **Download ZIP** (`POST /api/runs/export`). ZIPs keep every run ID as their
  top-level directory, so extracting one inside `security_pipeline_runs/`
  restores the selected runs. Symlinks are excluded deliberately, so an archive
  cannot include files outside a run directory.
- **fixPOV replay** — from an accepted run’s Workflow tab, rerun the
  current curated POV set against its preserved patched worktree. The action is
  asynchronous, shows progress and errors inline, and refreshes the coverage
  score without rerunning agents or changing the run verdict.
- **Group & compare** — the Experiments list groups runs by project (finding
  id); select two or more and open `/compare` for a side-by-side of profile,
  model, status, patch score, cost, and patch diffs — built for
  baseline-vs-full A/B.

The run **model** shown in the UI is the primary working model taken from
`modelUsage` by spend, not the internal helper model Claude Code also reports
(so runs correctly show e.g. `Opus 4.8 (1M)`).

## Roadmap

- **Phase 1 — Core dashboard (done).** Overview + run detail: workflow signal-rail,
  agent I/O, diffs, taint trace, container logs, and the ground-truth panel
  (CVE mapping, fix commits, official-fix localization + fetched fix diffs).
- **Phase 2 — Analysis agents** (in progress). See [`ANALYSIS_AGENTS.md`](ANALYSIS_AGENTS.md).
  - Reference-Patch agent (done) — deterministic official-fix extraction (fix
    localization + fetched fix diffs), `GET /api/runs/{id}/reference-patch`.
  - Patch Evaluation agent (done) — reference-anchored LLM judge, 8-dimension
    scorecard with gates + issues, on the run detail **Evaluation** tab.
    `POST/GET /api/runs/{id}/analysis/patch-eval`.
  - Exploitation Analysis agent (done) — LLM judge scoring the POV on 8
    dimensions with a conjunctive/differential oracle; Patch/Exploit toggle on
    the Evaluation tab. `POST/GET /api/runs/{id}/analysis/exploit-eval`.
  - CVE Research agent (done) — multi-source fetch (NVD/OSV/GHSA/KEV +
    Metasploit/Exploit-DB/Nuclei/PoC repos) + genuineness judge; CVE
    intelligence panel on the Ground truth tab; persists an official exploit
    that feeds the exploit judge's comparison.
    `POST/GET /api/runs/{id}/analysis/cve-research`.
  - **Phase 2 complete.**
- **Phase 3 — Live run (done).** Arm the pipeline against a finding from the
  **Live** page and watch it progress in real time: the backend spawns
  `python -m security_pipeline run`, discovers the run directory it creates
  (the finding-id is deterministic), and streams typed Server-Sent-Events over
  the run dir. The signal-rail animates stage-by-stage (the in-flight stage
  pulses with a live elapsed clock), the orchestrator stdout streams into a
  console, agents report turns/cost as they finish, and a terminal verdict links
  through to the full run. Granularity is stage + agent-boundary — the honest
  live signal, since each `claude`/`docker` call is a blocking subprocess.
  Recent launches are listable so the monitor can reconnect after a dropped
  stream. `POST /api/live/launch`, `GET /api/live/{id}/stream`.
- **Phase 4 — Deep oracle** (in progress).
  - **Ensemble judging (done).** Both LLM judges can run K times in parallel
    (`?samples=N`, 1–5) and report the *distribution* rather than a lucky draw:
    a median score with a confidence band, per-dimension spread and agreement,
    and band/gate agreement. The narrative (summary, rationales, issues) is taken
    from the *medoid* — the sample whose dimension scores sit closest to the
    per-dimension medians — so the prose always matches a real, internally
    consistent pass. This is the honest fix for the run-to-run LLM-judge variance
    the single-shot scorecards couldn't show. The **Evaluation** tab exposes it
    as an "Ensemble ×3" trigger next to the normal run; the scorecard grows an
    ensemble strip (distribution track + per-sample chips + confidence) and each
    rubric row shows its own spread.
  - **Token-level live streaming (done).** The pipeline's agent runner takes an
    opt-in `--stream` flag: agents run with `--output-format stream-json` and
    each event (thinking/response deltas, tool uses, turn boundaries) is teed to
    `agent_io/<name>/stream.jsonl` as it arrives. The default path is unchanged —
    streaming is a separate code path reconstructing the same final result, so
    every downstream parser keeps working. The Live monitor launches with
    `--stream`, folds the in-flight agent's stream into a compact activity view
    (phase, thinking/response tails, tools, turns, tokens), and pushes it as its
    own `agent` SSE frame. The **Live** page renders a "watch it think" pane that
    updates token-by-token — the original brief's live signal, deepened from
    stage-boundary to token level. (The full end-to-end demo needs a real
    pipeline run, which is arm64-Docker-gated on this host; the streaming
    plumbing is verified with a stub emitting real stream-json.)
  - **Execution-grounded oracles (not built).** AspectJ sink instrumentation,
    mutation-based oracle strength, and a CodeQL residual scan would ground the
    POV/patch verdicts in bytecode-level evidence rather than an LLM reading
    logs. These need the Docker/POV execution path, which is arm64-gated on this
    host — deferred until that path is reliable here.
- **Phase 5 — Experiment controls (done).** Profile + model selectors on the
  launcher; batch runs with a concurrency-limited scheduler; stop/delete from
  the UI; by-project grouping + a two-run compare view. The run-detail/live
  stage rail is filtered to the run's actual profile stages. Also fixed the run
  model display (Claude Code reports an internal helper model alongside the real
  worker; the UI now shows the primary model by spend). See the
  [Experiment controls](#experiment-controls) section. Backs the `security_pipeline`
  experiment profiles (`--profile full|baseline|baseline_eval|no_verifier`).
