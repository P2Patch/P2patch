# `/root/autosec-baselines/` on the server

Everything produced by running other papers' tools lives here, one directory per baseline, one
directory per batch. Kept **outside** `/root/autosec` so baseline output never mixes with the
pipeline's own runs.

```
/root/autosec-baselines/
└── san2patch/
    ├── run_batch.sh          the one command — detaches, logs, collects
    ├── README.md             this file
    └── runs/
        └── <batch>/          e.g. claude-haiku-45-tot-20260814-0930
            ├── manifest.json  model, image digest, host, load, start/finish, status counts
            ├── env.txt        the container's .env with secrets redacted
            ├── run.log        full stdout/stderr of the batch
            ├── summary.tsv    case_id · status · tries · has_patch
            └── gen_diff/      per-case artifacts, mirrored out of the container
                └── <CVE>/
                    ├── res.txt
                    ├── <batch>_<CVE>_success.diff       final patch (success only)
                    ├── <batch>_<CVE>_success.artifact   full execution trace
                    └── stage_0_<n>/
                        ├── <CVE>.diff                   selected patch for that attempt
                        ├── <CVE>_<k>.diff               each ToT candidate
                        ├── <CVE>.vuln.out               PoC test output
                        └── <CVE>_graph_output.json      complete LangGraph state (~200 KB)
```

## Running a batch

```bash
bash /root/autosec-baselines/san2patch/run_batch.sh
```

It detaches and logs to `runs/<batch>/run.log`. Defaults: `claude-haiku-4.5`, `tot`, all of VulnLoc.
Watch it with:

```bash
tail -f /root/autosec-baselines/san2patch/runs/<batch>/run.log
cat    /root/autosec-baselines/san2patch/runs/<batch>/summary.tsv
```

Environment overrides — each gets its own batch directory, so models never overwrite each other:

| var | default | notes |
|---|---|---|
| `MODEL` | `claude-haiku-4.5` | also `gpt-4o`, `gpt-4o-mini`, `gemini-1.5-pro`, … (needs the matching key in `/app/.env`) |
| `VERSION` | `tot` | the paper's arm; ablations: `no_context`, `no_comprehend`, `no_howtofix`, `cot`, `zeroshot` |
| `VULN_IDS` | `vulnloc` | or a comma-separated list of case ids |
| `WORKERS` | `1` | parallel cases |
| `BATCH` | auto | `<model>-<version>-<date>` |
| `SYNC_EVERY` | `300` | seconds between artifact syncs |

## Why the collector exists

San2Patch writes everything **inside** the container. `docker rm` would destroy a multi-hour run.
`run_batch.sh` mirrors `gen_diff_<batch>/` onto the server every 5 minutes and once at the end, so
the server copy is always at most 5 minutes stale. The batch's own stdout goes straight to
`run.log` on the server.

## What is captured, and what is not

**Captured:** every generated patch (final and all ToT candidates), the PoC test output, the full
LangGraph reasoning state per case, the per-case status, the batch log with timestamps, and full
provenance (image digest, baseline commit, local patch, model, host, machine load at start).

**Not captured — known gaps, worth knowing before writing them up:**

- **Token counts and $ cost.** San2Patch persists neither; the `tiktoken` use in
  `base_llm_patcher.py` is for logit bias, not accounting. To get a cost column either read the
  provider console for the batch's time window, enable LangSmith (`LANGCHAIN_TRACING_V2=true` plus a
  key in `/app/.env` — the URLs then land in `res.txt`), or reconstruct from
  `*_graph_output.json`. Their paper reports $0.48/case, so we need *some* comparable number.
- **Trustworthy wall-clock.** Timestamps are in `run.log`, but they only mean something on an idle
  machine. The pipeline was at load ~8.6/8 cores during the first run. `manifest.json` records
  `load_at_start` so a batch measured under contention can be identified and excluded later.
- **`CVE-2017-14745`.** The only one of the image's 66 cases with no `src/` tree, so it cannot be
  validated at all. It will appear as an error, not a failure — keep it out of denominators.

## Adding another baseline

Make a sibling directory (`/root/autosec-baselines/patchagent/`, `…/looprepair/`) with the same
`runs/<batch>/` shape. The point of the layout is that a later comparison script can walk
`*/runs/*/summary.tsv` without knowing anything about the individual tools.
