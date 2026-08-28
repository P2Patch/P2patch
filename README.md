# P2Patch

An automated security remediation pipeline that uses Claude Code agents to exploit, patch, and verify security vulnerabilities.

## Overview

P2Patch automates the end-to-end process of fixing security vulnerabilities:

1. **Exploiter** — Creates a proof-of-vulnerability (POV) test that reproduces the vulnerability
2. **Patcher** — Applies a fix to the vulnerability while maintaining POV isolation
3. **LLM Verifier** — Helps with manual review by inspecting the patch, rerunning project checks, and recommending whether to accept or reject the fix

The pipeline runs each agent inside a Docker container and validates outputs at each stage through configurable gates.

When you want to automatically test a project, the LLM verifier provides an
additional review pass: it examines the proposed change in context and runs the
project's tests, giving manual reviewers evidence to use when assessing the
patch.

By default it runs the full exploit → patch → verify sequence, but it supports **experiment profiles** that vary which stages run — for example a `baseline` profile that patches from the alert alone (no exploiter, POV, or verifier) so you can A/B whether exploitation helps the patcher produce a better fix. See [Experiment profiles](#experiment-profiles).

A web UI, **P2Patch Lab**, sits on top of the pipeline for browsing, evaluating, launching, and comparing runs — see [Dashboard](#dashboard-p2patch-lab).

## Getting the code and the data

Everything you need is in this repository — a plain clone is enough:

```bash
git clone git@github.com:P2Patch/P2patch.git
```

The CVE corpus, the per-project Dockerfiles and both curated POV families are
under `benchmark/` — 101 CVEs pinned to their vulnerable commit, with the
per-project build image and both certified POV suites.

Set `P2PATCH_BENCHMARK` to point at a checkout somewhere else — useful on a run
host that already holds the (tens of GB of) project sources on another volume.

### The paper's pipeline runs

The runs behind the paper's numbers are published separately, because they are
too large for this repository (`security_pipeline_runs/` is gitignored for the
same reason). You do **not** need them to run the pipeline yourself — only to
inspect the exact runs the paper reports.

**Download:** <!-- TODO(before submission): replace with the figshare private
share link, https://figshare.com/s/<token>. The item is currently an unpublished
draft, so neither its /account/ URL nor its DOI resolves for a reviewer. -->
_link to be added_

The download is ~2.6 GB and provides `security_pipeline_runs.tar.zst` together
with its own README. It is a snapshot of **505 completed runs** over the 101-CVE
corpus across five arms — haiku-4.5 `baseline`, and `hardening` on each of
haiku-4.5, deepseek-v4-flash, gpt-5.6-luna and glm-5.2:floor — 101 runs each,
over the identical set of findings.

```bash
# from the repository root
mkdir -p security_pipeline_runs
tar -I 'zstd -d --long=27' -xf /path/to/security_pipeline_runs.tar.zst -C security_pipeline_runs/
./dashboard/dev.sh          # every run is then browsable at http://localhost:8000
```

`--long=27` is **mandatory** on extraction: the archive was written with a 128 MiB
long-range window and zstd refuses windows above 8 MiB without a matching flag.
Needs `zstd` (`brew install zstd` / `apt install zstd`) and ~13 GB free.

Three things worth knowing before you unpack:

- **Each run's `worktree/` and `baseline_checkout/` were dropped** — that is what
  takes the snapshot from 139 GB to 2.4 GB. Everything read-only still works
  (run lists, diffs, agent transcripts including full `stream.jsonl` reasoning,
  container logs, verdicts, and every previously computed fixPOV, residual and
  gate score). The dashboard's three re-evaluation buttons — fixPOV replay,
  residual replay, verifier retrofit — and the POV-quality judge do not, since
  they read the patched tree out of the worktree.
- **Unpacking makes the pipeline skip these findings.** The skip check is keyed
  by `(finding_id, profile)`, so a `--profile baseline` or `--profile hardening`
  sweep would find all 101 alerts already done. Either run an arm the snapshot
  does not contain (`full`, `baseline_eval`, `no_verifier`), unpack into a
  second checkout used only for browsing, or pass `--rerun`.
- **These runs predate the "ground truth" → "fixPOV" rename**, so their results
  still sit under `ground_truth/` with a `ground_truth_eval` step. No migration
  is needed — every reader accepts the legacy names.

Nothing outside `security_pipeline_runs/` is required to *view* them: the
dashboard maps each run back to its CVE through `finder_results_filtered/` and
`benchmark/`, both of which ship with this repository.


## Requirements

- Python 3.10+
- Docker
- [Claude Code CLI](https://claudecode.ai) (`claude` binary)
- Git (for worktree creation)

## Setup

```bash
# Create virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate

# Install the pipeline (puts `security-pipeline` on PATH).
# It has no third-party dependencies — this only registers the command.
pip install -e .
```

Every `security-pipeline ...` command below is also runnable without installing,
as `python -m security_pipeline ...` from the repository root.

The dashboard has its own dependencies (FastAPI, uvicorn, httpx); `./dashboard/dev.sh`
installs them for you, or `pip install -r dashboard/backend/requirements.txt`.
Those are also what the full test suite needs:

```bash
python -m unittest discover -s tests
```

## Quick Start

```bash
# Fetch project sources for alerts
security-pipeline fetch

# Run against a single alert
security-pipeline run --alert path/to/alert.json

# Run against a specific CVE
security-pipeline run --cve CVE-2022-26884

# Run all alerts (already-run alerts are skipped automatically)
security-pipeline run --all --limit 10

# Bare `run` defaults to --all
security-pipeline run

# Force re-running alerts that already have a run directory
security-pipeline run --rerun

# Skip specific projects by CVE id, project slug, or alert filename
security-pipeline run --except CVE-2022-26884 CVE-2018-1002202
```

### Z.ai models (GLM 5.3, GLM 5.2, GLM 5.1)

The pipeline can run its agents directly against Z.ai's Anthropic-compatible
endpoint instead of Anthropic's:

| Model ID | Launcher label |
| --- | --- |
| `glm-5.2` | GLM 5.2 (Z.ai) |
| `glm-5.1` | GLM 5.1 (Z.ai) |

The list is an explicit allowlist (`ZAI_MODELS` in `security_pipeline/zai.py`);
exposing another GLM model is two edits — that tuple, plus a `MODELS` row in
`dashboard/backend/live.py`.

#### The config file

Credentials live in `~/.claude/settings-zai.json` — the same file Z.ai's own
Claude Code setup instructions produce. It is a normal Claude Code settings
file; only its `env` block is read:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
    "ANTHROPIC_AUTH_TOKEN": "your_zai_api_key",
    "API_TIMEOUT_MS": "3000000",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "glm-5.2",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "glm-5.2",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "glm-5.2"
  }
}
```

| Key | Required | Meaning |
| --- | --- | --- |
| `ANTHROPIC_BASE_URL` | yes | Z.ai's Anthropic-compatible endpoint. Without it the request goes to Anthropic under a GLM model name and fails late and confusingly, so a run is rejected at launch if it is missing. |
| `ANTHROPIC_AUTH_TOKEN` | yes | Your Z.ai API key (`ANTHROPIC_API_KEY` is accepted too). A placeholder such as `your_zai_api_key` counts as unset and is rejected at launch. |
| `API_TIMEOUT_MS` | no | Request timeout. GLM turns can be slow; Z.ai's stock file sets 3000000 (50 min). |
| `ANTHROPIC_DEFAULT_*_MODEL` | no | Ignored by the pipeline — **all three slots are overwritten** with the model the run selected, so a GLM run stays single-model. Z.ai's stock file points the haiku slot at a cheap `glm-4.5-air`, which would otherwise put Claude Code's background turns on a different model than the run is labelled with. |

Get an API key from <https://z.ai/manage-apikey/apikey-list>. Anything else in
the `env` block (proxy settings, extra timeouts) is passed through unchanged.

Set `P2PATCH_ZAI_SETTINGS` to read the config from somewhere else (the
pre-rename `AUTOSEC_ZAI_SETTINGS` is still honoured):

```bash
export P2PATCH_ZAI_SETTINGS=/path/to/settings-zai.json
```

#### Running

```bash
python -m security_pipeline run \
  --alert path/to/alert.json \
  --model glm-5.2 \
  --effort high
```

or pick the model in the dashboard launcher. Routing is per run: the config is
merged into the pipeline-owned per-agent `--settings` file and the `claude`
subprocess environment, and `~/.claude/settings.json` is **never** rewritten —
your own interactive Claude Code sessions are unaffected. Any `ANTHROPIC_*`
variable exported on the host is cleared first, so a machine that exports
`ANTHROPIC_API_KEY` for normal Claude use cannot half-authenticate a GLM run.
The key is passed only through the process environment and is omitted from
`agent_io/<agent>/settings.json`, which is persisted and served by the
dashboard.

A missing file, a missing base URL, or an unfilled placeholder key fails at
launch, before any Docker build or agent turn.

Note the Z.ai route has no generation API to reconcile billing against, so its
reported cost stays Claude Code's Anthropic-tariff *estimate*. For real billed
cost on GLM, use the OpenRouter route below.

### OpenRouter models (DeepSeek V4 Flash, GPT-5.6 Luna, GLM 5.3/5.2)

The pipeline can run its existing Claude Code agent harness against specific
OpenRouter models:

| Model ID | Launcher label |
| --- | --- |
| `deepseek/deepseek-v4-flash` | DeepSeek V4 Flash (OpenRouter) |
| `openai/gpt-5.6-luna` | GPT-5.6 Luna (OpenRouter) |
| `z-ai/glm-5.2:floor` | GLM 5.2 (OpenRouter, StreamLake FP8) |
| `z-ai/glm-5.2` | GLM 5.2 (OpenRouter, default routing) |

The list is an explicit allowlist (`OPENROUTER_MODELS` in
`security_pipeline/openrouter.py`), so a sibling slug such as
`openai/gpt-5.6-luna-pro` is not routed until it is added there and to the
dashboard's `MODELS` list. Note `z-ai/glm-5.2` (OpenRouter) and `glm-5.2`
(Z.ai direct) are two separate launcher rows for the same model on two
different routes; only the OpenRouter one reports the amount actually billed.

`:floor` is normally OpenRouter's price-sorted routing variant. P2Patch keeps
the `z-ai/glm-5.2:floor` launcher id for compatibility, but sends it as
`z-ai/glm-5.2@preset/autosec-glm52-streamlake`. That preset must allow only the
`streamlake/fp8` endpoint and disable fallbacks, so every request in this arm is
attributable to StreamLake's FP8 implementation. Create it once in the same
OpenRouter workspace as the API key:

```bash
curl https://openrouter.ai/api/v1/presets/autosec-glm52-streamlake/messages \
  -H "Authorization: Bearer $OPENROUTER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "z-ai/glm-5.2",
    "provider": {
      "only": ["streamlake/fp8"],
      "allow_fallbacks": false
    },
    "messages": []
  }'
```

OpenRouter presets are workspace-scoped. A missing preset makes the request
fail instead of falling back to a different endpoint. The plain
`z-ai/glm-5.2` row retains OpenRouter's default multi-provider routing, while
the other `:floor` rows retain ordinary price-sorted routing.

Set an OpenRouter key, then select the model from the dashboard or pass it to
the CLI:

```bash
export OPENROUTER_API_KEY="sk-or-..."
python -m security_pipeline run \
  --alert path/to/alert.json \
  --model openai/gpt-5.6-luna \
  --effort high
```

`high` and `xhigh` are the reasoning efforts supported by DeepSeek V4 Flash; the
launcher default (`high`) is valid for every model on the list. Instead of
exporting the key, it can be stored in `~/.claude/settings-openrouter.json`:

```json
{
  "env": {
    "OPENROUTER_API_KEY": "sk-or-..."
  }
}
```

Set `P2PATCH_OPENROUTER_SETTINGS` to use a different file (the pre-rename
`AUTOSEC_OPENROUTER_SETTINGS` is still honoured). The integration is
applied only to the spawned `claude` process: it uses OpenRouter's Anthropic
endpoint (`https://openrouter.ai/api`), pins every Claude Code model slot to the
selected OpenRouter model, and never rewrites `~/.claude/settings.json`. The key
is passed through the process environment and is omitted from persisted run
artifacts.

Claude Code's terminal `total_cost_usd` applies its own fallback tariff to an
OpenRouter model and is not the amount OpenRouter billed. OpenRouter runs retain
their event stream even without `--stream`, then resolve each saved `gen-*` ID
through OpenRouter's generation API. The exact per-agent charge is cached in
`agent_io/<agent>/provider_cost.json`; the dashboard uses it only when every
generation resolved successfully, otherwise it keeps Claude's estimate and the
incomplete cache explains why reconciliation failed.

## CLI Commands

### run

Run the exploiter -> patcher -> verifier pipeline.

```
security-pipeline run [options]

Target (pick one; defaults to --all when none is given):
  --alert PATH       Path to a finder alert JSON file
  --cve CVE_ID       CVE ID to run from the alerts directory
  --all              Run every alert in the alerts directory

Options:
  --workspace-root PATH    Workspace root (default: cwd)
  --alerts-dir PATH        Filtered alerts directory (default: finder_results_filtered)
  --runs-dir PATH          Run output directory (default: security_pipeline_runs)
  --profile NAME           Experiment arm / stage recipe (default: full).
                           One of: full, baseline, baseline_eval, no_verifier
  --stages a,b,c           Ad-hoc stage override (advanced ablations); takes
                           precedence over the profile's stage list
  --patcher-evidence {full,alert_only}
                           Whether the patcher is shown the exploit evidence
                           (default: derived from --profile)
  --max-correction-attempts N
                           Max patcher attempts at each objective patch gate —
                           POV-after, regressions, and each hardening round
                           (min 1, default 3). A failing check is fed back to the
                           patcher and re-checked; 1 = the old one-shot gates that
                           reject on the first failure. Keep equal across arms in
                           a baseline-vs-full A/B.
  --max-exploit-attempts N Max exploiter attempts at a POV that reproduces on the
                           unpatched code (min 1, default 3). A POV that does not
                           reproduce is fed back to the exploiter; 1 = the old
                           one-shot gate.
  --model TEXT             Claude alias/name or configured provider model ID
  --effort TEXT            Claude effort level (default: high)
  --stream                 Stream agent output (stream-json) to
                           agent_io/<name>/stream.jsonl for live monitoring
  --claude-bin TEXT        Claude Code executable (default: claude)
  --permission-mode TEXT   Claude permission mode (default: bypassPermissions)
  --agent-timeout-seconds  Agent timeout (default: 3600)
  --command-timeout-seconds Command timeout (default: 1800)
  --dry-run                Write context/state only; do not invoke Docker or Claude
  --skip-docker-build      Assume the computed Docker image already exists
  --limit INT              Limit number of alerts to run (applied after skipping)
  --except ID [ID ...]     Skip alerts matching a CVE id, project slug, or alert
                           filename (alias: --exclude)
  --rerun                  Re-run alerts even if a prior run directory exists
                           (alias: --force)
```

### Skipping already-run alerts

By default, `run` skips any alert that already has a run directory under
`--runs-dir` (matched by the alert's stable `finding_id`), so re-running
`security-pipeline run` only processes alerts that have not been run yet. A
`--dry-run`-only directory does not count as a prior run. Pass `--rerun` to
force re-running, and `--except` to skip specific projects. Skipped alerts are
reported with `"status": "skipped"`.

### Experiment profiles

The pipeline is a sequence of discrete **stages** (`worktree`, `docker_build`,
`exploiter`, `patcher`, `converge`, `harden`, `verifier`). `--profile`
selects which stages run and whether the patcher is shown the exploit
evidence — the core knob for measuring whether exploitation helps the patcher
produce a better fix.

The `converge` stage runs the POV-after and regression checks as a
**self-correction fix-point** — see [Self-correction](#self-correction).

| Profile | Stages | Patcher sees the POV? |
|---|---|---|
| `full` (default) | exploiter → patcher → converge → verifier | yes |
| `baseline` | worktree → docker_build → patcher → verifier | no — no exploiter or POV |
| `baseline_eval` | same as `full` | no — the exploiter still builds the scorer, but its output is withheld from the patcher |
| `no_verifier` | `full` minus the verifier gate | yes |

`baseline` produces a patch from the alert alone, but that patch is still
reviewed by the verifier, which needs no POV — it has an alert-only evidence
mode where it judges the diff against the alert instead of against an exploit,
and runs the project's tests itself to check the patch did not break anything.
Withholding review made the arms differ in *gating* as well as in evidence,
which is not the comparison the study is trying to make. There is deliberately
no separate `regression` stage here: that gate exists to feed a broken test back
to the patcher, and this arm has no self-correction loop.
`baseline_eval` runs the exact same objective gates as `full` *and* builds a POV
to score with, so it remains the tightest A/B. The skip-if-already-run check is
profile-aware, so you can run `baseline` over projects that already have a
`full` run without `--rerun`, and each run records its `profile` in
`state.json`/`verdict.json`.

```bash
security-pipeline run --all --profile full            # full pipeline (default)
security-pipeline run --all --profile baseline        # alert-only patches
security-pipeline run --all --profile baseline_eval   # controlled comparison
```

### Retrofitting gates onto finished runs

Runs recorded before `baseline` gained the verifier can be brought up to the
same standard without re-running the pipeline:

```bash
security-pipeline retrofit --dry-run          # list eligible runs and exit
security-pipeline retrofit                    # verifier over every accepted `baseline` run
security-pipeline retrofit --project <slug>   # one project
security-pipeline retrofit --gates regression # a non-default gate (not a baseline stage)
```

This is **assess-only**. It replays the gates against the patch already on disk
and records whether that patch *would* have cleared them; it never sends the
patcher back, so the diff, the run's `status`, and the fixPOV/residual
scores computed from that diff all stay exactly as they were. The outcome lands
in `security_pipeline_runs/<run>/gates/results.json` and a `retrofit_gates`
field, and the replayed stages join the run's stage list so the dashboard rail
shows them.

A gate the run already ran natively is skipped rather than overwritten (use
`--force` to override). A gate the retrofit could not *complete* — a crashed
agent, a container error — is recorded as `errored`, never as a failure, and is
retried automatically on the next invocation.

### Self-correction

A failing objective check is not a verdict — it goes back to the agent that owns
it, with the failure as feedback.

**The patcher** (`--max-correction-attempts`, default 3) is sent back whenever a
gate on its patch fails: the POV still reproduces after patching, a regression
test broke, or (in `hardening`) a round's bypass variant survived the
strengthened fix. This applies to the `converge` stage in `full` /
`baseline_eval` / `no_verifier`, to the standalone `pov_after` and `regression`
stages in `hardening`, and to each hardening round. Every attempt re-checks the
POV **before** the tests, so a change made to fix a regression can never silently
re-open the vulnerability, and the regression command set can only grow — a
correcting patcher cannot drop the tests it is judged by.

**The exploiter** (`--max-exploit-attempts`, default 3) is sent back when its POV
does not reproduce on the unpatched code (or its output fails a gate), which is
an objectively broken POV rather than a reason to abandon the run. A crashed or
policy-refused agent is not retried.

Setting either budget to `1` restores the old one-shot behavior, where the first
failing check rejects the run.

```bash
# Old one-shot gates: reject on the first failing check.
security-pipeline run --all --profile full --max-correction-attempts 1 --max-exploit-attempts 1
```

Because self-correction changes what the agents are measured on ("fixed in N
attempts" vs "fixed in one shot"), keep both budgets equal across arms in a
baseline-vs-full A/B. Each run records them in `state.json`/`verdict.json`, and
every retry keeps its own agent-IO folder (`patcher_correction_*`,
`exploiter_retry_*`) so the attempt that fixed it is inspectable.

### fixPOV evaluation

Every profile ends in a **non-gating** `fix_pov_eval` step. It replays a
project's *curated fixPOVs* — real exploits derived from the CVE's
advisory and fix commit, checked in under `benchmark/fix_povs/<project_slug>/` and
certified once to reproduce on the unpatched code and be blocked by the official
fix — against the pipeline-patched code. The result is a **coverage score**
(fraction of real exploit paths the patch blocked), written to
`security_pipeline_runs/<run>/fix_pov/results.json` and shown in the
dashboard. It is a *metric only* — it never rejects a run.

```bash
# Which local project sources you can author POVs for
security-pipeline fixpov list-projects

# Coverage / certification status across all curated projects
security-pipeline fixpov status

# Certify a project's POVs (builds it, runs each POV before/after the official fix)
security-pipeline fixpov validate --project srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2

# Replay newly authored POVs against this project's already-completed runs.
# Each run is reconstructed from the vulnerable revision + the patch it produced,
# so this still works after the (multi-GB) run worktrees have been pruned.
security-pipeline fixpov replay --project srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2

# ...or score the runs' preserved worktrees, the way replay used to
security-pipeline fixpov replay --project srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2 --from-worktree

# Skip the fixPOV eval stage for a run
security-pipeline run --alert path/to/alert.json --no-fix-pov-eval
```

To author POVs for a new project, follow `benchmark/fix_povs/GENERATING_POVS.md`
(hand it to a coding agent, one project at a time). See
`benchmark/fix_povs/README.md` for the contract and layout.

### fetch

Fetch IRIS project sources from GitHub based on alerts.

```
security-pipeline fetch [options]

Options:
  --workspace-root PATH    Workspace root (default: cwd)
  --alerts-dir PATH        Filtered alerts directory (default: finder_results_filtered)
  --projects-dir PATH      Output directory for cloned projects
  --limit INT              Limit number of projects to fetch
  --timeout-seconds INT    Git clone timeout (default: 300)
```

## Project Structure

```
P2Patch/
├── security_pipeline/
│   ├── __init__.py          # Package metadata
│   ├── __main__.py          # Entry point
│   ├── cli.py               # CLI argument parsing
│   ├── pipeline.py          # Core pipeline orchestration (stage runner)
│   ├── stages.py            # Pipeline stages + experiment profiles
│   ├── claude_agents.py     # Claude Code agent runner
│   ├── docker_runner.py     # Docker build and command execution
│   ├── gates.py             # Output validation gates
│   ├── logging_io.py        # File I/O utilities
│   ├── metadata.py          # Alert and project metadata loading
│   ├── models.py            # Data classes
│   ├── workspace.py         # Git worktree and diff utilities
│   ├── prompts/             # Agent system prompts
│   │   ├── exploiter.md
│   │   ├── patcher.md
│   │   └── verifier.md
│   └── schemas/             # Agent output JSON schemas
│       ├── exploiter.json
│       ├── patcher.json
│       └── verifier.json
├── tests/
│   └── test_security_pipeline.py
├── benchmark/               # CVE corpus, Dockerfiles, POV suites
│   ├── dataset/
│   │   ├── project_info.csv
│   │   ├── build_info.csv
│   │   ├── fix_info.csv
│   │   ├── project-sources/   (gitignored)
│   │   └── Dockerfiles/
│   ├── fix_povs/            # "did the patch close the CVE?" suites
│   └── residual_povs/       # "did the patch beat upstream?" suites
├── finder_results_filtered/ # Security alert JSON files
├── security_pipeline_runs/  # Pipeline run outputs
└── dashboard/               # P2Patch Lab web UI (FastAPI + React)
```

## How It Works

1. **Alert Loading** — Parses a security alert JSON and resolves project metadata from CSV files
2. **Worktree Creation** — Creates an isolated git worktree for the run
3. **Docker Build** — Builds a project-specific Docker image
4. **Exploiter Agent** — Claude creates a POV test that reproduces the vulnerability
5. **POV Validation** — Runs the POV in Docker to confirm it works before
   patching. A POV that does not reproduce goes back to the exploiter
   (see [Self-correction](#self-correction))
6. **Patcher Agent** — Claude patches the vulnerability in the worktree
7. **Converge** — Verifies the patch holds: the POV no longer reproduces *and*
   the regression suite passes. A failing check is fed back to the patcher and
   re-checked instead of rejecting the run
   (see [Self-correction](#self-correction))
8. **Verifier Agent** — Claude reviews the full context and accepts/rejects the patch

This is the `full` profile; other profiles run a subset of these stages — see [Experiment profiles](#experiment-profiles).

## Run Output

Each run produces a directory under `security_pipeline_runs/` containing:

- `state.json` — Pipeline state and step history
- `verdict.json` — Final acceptance/rejection verdict
- `context.json` — Full context passed to agents
- `git/` — Diff files (full, patch-only, POV)
- `docker/` — Docker command logs
- `agent_io/` — Agent inputs, outputs, and raw stdout/stderr

The 505 runs behind the paper's numbers are published as a separate download —
see [The paper's pipeline runs](#the-papers-pipeline-runs).

## Dry Run

Generate context and state without running Docker or Claude:

```bash
security-pipeline run --alert alert.json --dry-run
```

## Dashboard (P2Patch Lab)

`dashboard/` is a web UI for browsing, evaluating, launching, and comparing
pipeline runs. It reads the on-disk run artifacts (never mutates them), maps
each redacted run back to its real CVE and official fix, and can launch runs
live.

![P2Patch Lab — an accepted run on commons-io CVE-2021-29425: the stage rail
(exploiter → POV → patcher → POV-after → regressions → verifier), the acceptance
verdict, and the held-out fixPOV coverage score.](docs/dashboard-run.jpg)

- **Browse & evaluate** — per-run signal-rail, agent I/O, diffs, container
  logs, fixPOV panel, and LLM-judge scorecards for patch and POV quality
  (with optional ensemble judging).
- **Live runs** — arm a finding and watch each stage stream in real time
  (token-level agent activity), with **profile** and **model** selectors. The
  workflow rail reflects the selected profile's stages.
- **Batch runs** — select multiple findings and queue them; a scheduler runs
  them up to a chosen **concurrency** (default 1), starting the next as each
  finishes. Stop queued or running launches.
- **Compare** — group runs by project and put two side by side (profile, model,
  status, patch score, cost, and patch diffs) — built for baseline-vs-full A/B.
- **Manage & share** — stop an active run or delete a run directory from the
  UI; download a single run or a selected set as a portable ZIP. Extract the
  ZIP in `security_pipeline_runs/` to restore its run folders.

Run it (build the UI + serve everything on http://localhost:8000):

```bash
./dashboard/dev.sh
```

For hot-reload development and the full API reference, see
[dashboard/README.md](dashboard/README.md).

## License

Internal use only.
