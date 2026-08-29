<!--
Source of truth for the README bundled inside `autosec_runs_backup.zip` on figshare.

It lives here so it cannot drift from the repository README again: the uploaded copy once carried a
GNU-only `tar -I` invocation that fails on macOS, a `pip install -r requirements.txt` that never puts
`security-pipeline` on PATH, and a dead Claude Code link. Edit this file, then re-upload it alongside
the tarball; keep the commands in the Restore and Re-running sections in step with README.md.
-->

# P2Patch run artifacts — `security_pipeline_runs.tar.zst`

This archive is a snapshot of `security_pipeline_runs/` from the P2Patch pipeline
(<https://anonymous.4open.science/r/P2patch-4986>): 505 completed runs covering the 101-CVE corpus across
five experiment arms (haiku-4.5 `baseline`, haiku-4.5 `hardening`, deepseek-v4-flash `hardening`,
gpt-5.6-luna `hardening`, and glm-5.2:floor `hardening` — 101 runs each, all five over the identical set
of 101 findings). Each run directory holds everything the dashboard reads: `state.json` (step history),
`verdict.json` (final verdict + profile), `context.json`, the `git/` diffs (`full.diff`,
`patch_only.diff`, `pov.diff`), `docker/` command logs, `agent_io/` per-agent inputs, outputs and full
`stream.jsonl` transcripts (including the agents' verbatim reasoning), plus the fixPOV, residual, gate
and analysis results where those stages ran. The large, regenerable parts are **not** included — each
run's `worktree/` and `baseline_checkout/` checkouts were excluded, which is what takes the snapshot from
139 GB down to 2.4 GB. To use it, get the repository, unpack this archive into a
`security_pipeline_runs/` directory at the repository root, and start the dashboard — every run is then
browsable in P2Patch Lab exactly as it was on the machine that produced it.

## Restore

Download the repository as a zip from
<https://anonymous.4open.science/api/repo/P2patch-4986/zip> (the anonymized host serves a zip; it does
not support `git clone`), then:

```bash
curl -L -o P2patch.zip https://anonymous.4open.science/api/repo/P2patch-4986/zip
unzip P2patch.zip -d P2patch
cd P2patch                  # if the zip holds a single top-level folder, cd into that instead
mkdir -p security_pipeline_runs
zstd -d --long=27 -c /path/to/security_pipeline_runs.tar.zst | tar -xf - -C security_pipeline_runs/

chmod +x dashboard/dev.sh   # the anonymized zip does not preserve the executable bit
./dashboard/dev.sh          # builds the frontend and serves on http://localhost:8000
```

`--long=27` on extraction is **mandatory** — the archive was written with a 128 MiB long-range window,
and zstd's CLI refuses windows above 8 MiB unless you opt in with a matching `--long`. Requires `zstd`
(`apt install zstd` / `brew install zstd`) and ~13 GB of free disk for the unpacked tree.

The pipe above is used instead of `tar -I 'zstd -d --long=27' -xf ...` because `-I` is GNU tar only: on
macOS, BSD tar reads it as an *inclusion pattern* and fails with `Error inclusion pattern`. The pipe
works with both tars.

Nothing outside `security_pipeline_runs/` is needed to *view* the runs: the dashboard resolves each run
back to its CVE through files that ship with the repository — `finder_results_filtered/` (the alert
JSONs) and `benchmark/`, which holds the corpus metadata (`benchmark/dataset/project_info.csv`,
`benchmark/dataset/fix_info.csv`) and both POV families (`benchmark/fix_povs/`,
`benchmark/residual_povs/`).

These runs predate the "ground truth" → "fixPOV" rename, so their per-run results still sit in a
`ground_truth/` subdirectory and their stage/step is still called `ground_truth_eval`. That is expected
and needs no migration: run artifacts are read-only history, and the dashboard accepts the legacy names
as a fallback everywhere it reads them.

## Re-running the pipeline

Viewing needs nothing but the repository. *Producing* new runs additionally needs Python 3.10+, Docker,
Git, and the [Claude Code CLI](https://claude.com/claude-code) (`claude` on your PATH), plus the project
sources, which are not in this archive and are fetched separately:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .                                         # puts `security-pipeline` on PATH
security-pipeline fetch                                  # clone the project sources for the alerts
security-pipeline run --all --profile hardening --model <model>
```

The pipeline itself has no third-party dependencies — `pip install -e .` only registers the command.
Every `security-pipeline ...` call is also runnable without installing, as `python -m security_pipeline
...` from the repository root.

**Unpacking this snapshot will make the pipeline skip everything in it.** The skip check is keyed by
`(finding_id, profile)`, so with these 505 runs on disk a `--profile baseline` or `--profile hardening`
sweep finds all 101 alerts already done and does nothing. Three ways round it, in order of preference:

- **Run a different arm** — a profile not in the snapshot (`full`, `baseline_eval`, `no_verifier`) is not
  skipped, so nothing needs moving.
- **Unpack somewhere else** — restore into a second copy of the repository used only for browsing, and
  keep the working copy's `security_pipeline_runs/` empty.
- **`--rerun`** — forces the alerts through regardless. Note new runs land in the *same* directory
  alongside these, so back the snapshot up first if you want the arms kept clean.

Re-running is not free: each run drives several agent turns inside a Docker container, and the five arms
here took days of wall time. Start with `--limit`, or `--alert path/to/one.json`, before any `--all`.
Add `--jobs N` for concurrency and `--dry-run` to check wiring without touching Docker or Claude.

## What you cannot do with this snapshot

Because the per-run `worktree/` directories were dropped, the dashboard's three re-evaluation buttons —
fixPOV replay, residual replay, and verifier retrofit — will not work against these runs, and neither
will the POV-quality judge, which reads the POV sources out of the worktree. Everything read-only (run
lists, diffs, agent transcripts, docker logs, verdicts, and all previously computed fixPOV, residual and
gate scores) works normally.
