# San2Patch baseline

How we ran San2Patch (Kim et al., USENIX Security 2025) for the published-system
comparison in the paper.

| | |
|---|---|
| Code | San2Patch @ `a8c5ace939cd` (MIT), pinned in `../pins.json` |
| Benchmark | san2patch-benchmark @ `cd54141e4e15` (MIT) |
| Image | `acorn421/san2patch` (amd64 only, about 16 GB) |
| Model | Claude Haiku 4.5, added through `0001-add-claude-haiku-4-5.patch`, so that every system in the comparison uses the same model |
| Configuration | the paper's Tree-of-Thought setting (`tot`) |

`./run_one.sh <bug_id>` runs one VulnLoc case; the resulting patches are
normalized to `../schema/baseline_result.schema.json` under
`../results/san2patch/` and re-scored with `../score_patches.py`.

## How a run works

## Architecture: Docker-in-Docker

`acorn421/san2patch` is not a plain app image. Its `ENTRYPOINT` (`entrypoint.sh`) does four things
before your command runs:

1. `source .env` — loads API keys and dataset paths
2. `start-docker.sh` — starts an **inner dockerd**
3. `scripts/start_aim.sh` — starts the AIM experiment-tracking stack
4. `docker run -d --name san2patch-benchmark acorn421/san2patch-benchmark:latest` — launches the
   **benchmark container inside itself**

So there are two containers. The **agent** (outer) does LLM reasoning and writes patches; the
**benchmark** (inner) does every build, PoC replay and functional test. That is why the outer
container needs `--privileged`, and why a run that "fails" can mean the inner container never came
up — check that before blaming the patch.

The dataset is **pre-baked into the image** at `/app/benchmarks/final/final-test/`, so there is no
dataset setup step. (`scripts/prepare_san2patch_benchmark.sh` exists for building it from scratch;
the authors recommend against it because some repos contain symlinks that don't survive.)

## The single command

Everything above is bootstrap. The actual run is one command:

```bash
python ./run.py Final run-patch \
  --vuln-ids "CVE-2017-14745" \
  --model "claude-haiku-4.5" \
  --version tot \
  --experiment-name "autosec-cve-2017-14745"
```

Run inside the container, from `/app`. `run_one.sh` in this directory wraps it with the two
preflight checks that matter (outer container up, inner benchmark container up).

Useful flags: a positional `NUM_WORKERS` (default 1) for parallelism; `--vuln-ids vulnloc` to run
the whole VulnLoc set instead of one case; `--retry-cnt` / `--max-retry-cnt` for the retry budget;
`--version` to select the prompting arm (`tot` is the paper's, others are its ablations:
`no_context`, `no_comprehend`, `no_howtofix`, `cot`, `zeroshot`).

## Where everything lands

All under `/app/benchmarks/final/final-test/gen_diff_<experiment_name>/<vuln_id>/`:

| path | what |
|---|---|
| `res.txt` | **read this first** — one line per attempt with a status code, plus LangSmith trace URLs |
| `<exp>_<vuln_id>_success.diff` | the final patch, **only written if the run succeeded** |
| `<exp>_<vuln_id>_success.artifact` | full LangGraph execution trace for the successful run |
| `stage_0_<stage_id>/<vuln_id>.diff` | the final generated patch for that attempt |
| `stage_0_<stage_id>/<vuln_id>_<variant>.diff` | each candidate patch the ToT search produced |
| `stage_0_<stage_id>/<vuln_id>.vuln.out` | output of the vulnerability (PoC) test |
| `stage_0_<stage_id>/<vuln_id>_graph_output.json` | complete LangGraph reasoning state — every stage's prompt and answer |

The `stage_0_*` directories are where the interesting failure analysis lives: the ToT search
generates multiple candidates per case, and only one is promoted.

## Status codes in `res.txt`

| code | meaning |
|---|---|
| `success` | patch applied, compiled, blocked the PoC, **and** passed the functional tests |
| `build_failed` | the patch broke compilation |
| `vuln_test_failed` | compiled, but the PoC still reproduces — the vulnerability is not fixed |
| `func_test_failed` | compiled and blocked the PoC, but broke the project's own tests |

Note this is exactly the three-gate criterion from the paper, and `func_test_failed` is the
category their Table 4 says is large — only ~30% of vulnerability-fixing patches preserved
functionality. Expect it.

## Monitoring a run in progress

```bash
docker logs -f san2patch                       # entrypoint + bootstrap
docker exec san2patch tail -f /app/logs/*.log  # agent logs (path varies by run)
watch -n30 'docker exec san2patch cat /app/benchmarks/final/final-test/gen_diff_<exp>/<vuln>/res.txt'
```

If `LANGCHAIN_TRACING_V2=true` and a LangSmith key are set, every LLM call is traceable in the
LangSmith UI and the URLs are written into `res.txt`. We are not setting that up for the first run —
it needs a third-party account and the local artifacts are enough.

## Getting results out

```bash
docker cp san2patch:/app/benchmarks/final/final-test/gen_diff_<exp> ./out/
```

Then normalize into `../schema/baseline_result.schema.json` and commit under
`../results/san2patch/<batch>/`. Never commit the raw `gen_diff_` tree — it carries full LLM traces.
