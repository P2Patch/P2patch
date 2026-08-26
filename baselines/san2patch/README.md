# San2Patch — runbook

_Status 2026-08-13: code + benchmark cloned and pinned; not yet run. Blockers below._

## What we have

| | |
|---|---|
| Paper | `~/Downloads/usenixsecurity25-kim-youngjoon.pdf` (read; Table 1 transcribed to `../paper_reported/san2patch_table1.json`) |
| Code | `../vendor/san2patch` @ `a8c5ace939cd`, MIT |
| Benchmark | `../vendor/san2patch-benchmark` @ `cd54141e4e15`, MIT |
| Prebuilt image | `acorn421/san2patch` — **16 GB**, 28 layers, **single-arch manifest** |

## Their evaluation set — and what we do/don't have

The benchmark ships **two** datasets, not one:

| set | cases | subjects | in our dataset | have an alert |
|---|---|---|---|---|
| `vulnloc-meta-data.json` | 43 | binutils, coreutils, **ffmpeg**, jasper, libarchive, libjpeg, libming, libtiff, libxml2, potrace, zziplib | **37 / 43** | 35 / 43 |
| `san2patch-meta-data.json` (San2Vuln) | 27 | **bento4, kamailio, liblouis**, libming | **0 / 27** | 0 / 27 |

**Missing from our dataset (6 VulnLoc cases):**
`CVE-2016-10094`, `CVE-2016-9273` (libtiff) · `gnubug-25003`, `gnubug-26545` (coreutils) ·
`CVE-2017-9992`, `bugchrom-1404` (ffmpeg — the project is absent from our set entirely)

**In our dataset but with no alert (2):** `CVE-2018-14498`, `CVE-2018-19664` (libjpeg)

**San2Vuln is a different benchmark.** Its 27 cases are post-Aug-2024 vulns in bento4, kamailio and
liblouis — projects we do not have at all — plus two 2024 libming CVEs distinct from ours. Adding it
would mean onboarding three new projects. It is where San2Patch scores its *weaker* result (63% vs
79.5%), so it is worth having eventually, but it is not the comparison set.

> **Terminology correction.** We did **not** clone VulnLoc+, and VulnLoc+ is not a reduced VulnLoc.
> `san2patch-benchmark` ships **VulnLoc (43)** and **San2Vuln (27)**. **VulnLoc+** is *LoopRepair's*
> name for VulnLoc **plus** 12 CrashRepair cases — an extension. Our own 43 C/C++ cases are
> 37 VulnLoc + 6 CrashRepair "RED-TEAM", i.e. ours is the VulnLoc+-shaped set. San2Patch itself
> evaluates on 39 of the 43, dropping `bugchrom-1404`, `CVE-2017-9992`, `CVE-2016-3186` and
> `CVE-2016-5314` as irreproducible under sanitizer instrumentation.

**To run their agent on their dataset we need nothing from our repo.** The benchmark is
self-contained: per case it ships `config.sh` / `build.sh` / `test.sh` (security) and
`config_func.sh` / `build_func.sh` / `test_func.sh` (functional), plus the PoC under `tests/`.
Our alerts only matter later, when comparing against our runs.

## Blocker 1 — the API key (have one, verified)

Required. `.env_example` accepts `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`; one
suffices. For Anthropic, `langchain_anthropic.ChatAnthropic` is the client.

A key is stored in `../.env` (gitignored, mode 600) and verified working against
`claude-haiku-4-5-20251001`. **It was pasted into a chat transcript, so treat it as exposed and
rotate it once the experiments are done.**

## Blocker 2 — every model San2Patch can talk to is retired

Their Anthropic support is **hardcoded to four 2024 models** (`san2patch/utils/enum.py`,
`san2patch/patching/llm/anthropic_llm_patcher.py`, `run.py`). Tested against the live API:

| their `--model` | resolves to | status |
|---|---|---|
| `claude-3-haiku` | `claude-3-haiku-20240307` | **HTTP 404 — retired** |
| `claude-3.5-sonnet` | `claude-3-5-sonnet-20240620` | **HTTP 404 — retired** |
| `claude-3-opus` | `claude-3-opus-20240229` | **HTTP 404 — retired** |
| `claude-3-sonnet` | `claude-3-sonnet-20240229` | **HTTP 404 — retired** |

So San2Patch **cannot run on Anthropic at all as shipped** — not just "would run an old Haiku".
Reproducing their Anthropic numbers is impossible; those models no longer exist. (Their headline
79.5% is `gpt-4o-2024-08-06` anyway; Claude-3.5-Sonnet was a secondary result at 28/39.)

**The patch is mandatory, not optional**: add a `Claude45HaikuPatcher` pointing at
`claude-haiku-4-5-20251001`, register it in `enum.py` and the `run.py` dispatch. Three files, a few
lines. It modifies vendored code, so it lives here as a patch file applied at setup — never
committed into `vendor/`.

Consequence for the comparison: the "reproduce their paper first" step must use **OpenAI
`gpt-4o-2024-08-06`** (their actual headline config, and Table 1 is per-case for exactly that), while
the head-to-head against our runs uses `claude-haiku-4-5-20251001` to match our deployment. Two
different keys, two different purposes — asymmetry **C** in `../../BASELINE_COMPARISON.md` cannot be
closed on the Anthropic side.

## Blocker 3 — where to run: the server, not the Mac

**Do not run this on the Mac.** Not primarily a speed argument:

| | local Mac | server (2.28.1.51) | San2Patch's own eval env |
|---|---|---|---|
| arch | **arm64** | **x86_64** | x86_64 (Xeon Gold 5218) |
| CPU / RAM | 12 / 24 GB | 8 / 15 GB | 32 / 64 GB |
| free disk | 47 GB | **12 GB of 301 GB (97% used)** | — |

Confirmed from the registry: `acorn421/san2patch` is **`architecture: amd64, os: linux`** with no
arm64 variant. On an Apple Silicon Mac it therefore runs under Rosetta/qemu emulation.

1. **ASan under emulation is the real risk.** AddressSanitizer reserves a large fixed shadow-memory
   region at startup; under emulation that mapping frequently fails. The usual failure is loud (the
   binary dies before `main`), which costs time rather than correctness — but it can also degrade,
   and 43 cases × 2 builds each is a lot of surface for it.
2. **Speed.** Emulated x86_64 compile-heavy work runs roughly 5–20× slower. The benchmark base is
   `ubuntu:18.04` building old C projects with clang — the most emulation-hostile workload there is.
3. **Their own environment was x86_64** (Xeon Gold 5218, Ubuntu 22.04), as is our server, so running
   there removes the variable entirely.

*Note (correction to an earlier draft of this file): the "arm64 changes memory layout so PoCs may
not reproduce" argument does **not** apply here. Because the image is amd64 and runs emulated, the
guest is still x86_64 and layout is preserved. The case for the server rests on ASan-under-emulation
reliability and speed, not on layout divergence. A native arm64 rebuild would raise the layout
problem — but nobody is proposing that.*

**Server storage, as of 2026-08-13.** A 300 GB Hetzner Cloud Volume (`/dev/sdb`) has been attached
and is persistent (`/etc/fstab`, `nofail,discard,defaults`) at `/mnt/HC_Volume_106612992` — but it
is **empty and unused**: 280 GB free, 28 K used. Docker does not point at it.

Root is still the constraint: 277 GB used, **12 GB free**, and the San2Patch image alone is 16 GB.
Where the space actually went:

| path | size |
|---|---|
| `/var/lib/containerd` | **198 GB** |
| `/root/autosec/security_pipeline_runs` | 51 GB |
| `/root` (rest) | 21 GB |
| `/var/lib/docker` | ~5 GB |

Note the images live under **containerd**, not `/var/lib/docker` — this daemon runs
`dockerd --containerd=/run/containerd/containerd.sock`, so the containerd image store holds them.
That also explains why `docker system df` reports 185 GB against a 5 GB `/var/lib/docker`.

**Pruning will not help.** Only **1 dangling image** and 3 stopped containers exist. `docker system
df`'s "81 GB reclaimable" is computed on summed per-image virtual size and double-counts shared
layers. A real `docker image prune` frees almost nothing; `prune -a` would delete all 216 images
including every project image the pipeline depends on, and the layer cache is what makes its
rebuilds ~2s (see the root `CLAUDE.md`).

So one of these has to happen, and both need the pipeline idle (4 agent processes were running):

1. **Move `security_pipeline_runs` (51 GB) to the volume and symlink it back.** Frees 51 GB → ~63 GB
   on root, enough for the image plus 43 cases of build output. Touches only our data, no Docker
   restart, transparent to the dashboard. **Recommended first step.**
2. **Relocate containerd's root to the volume** (`/etc/containerd/config.toml` `root =`, plus
   `data-root` in `daemon.json` for the ~5 GB Docker side), rsync 198 GB, restart both services.
   The proper long-term fix — gives Docker the full 280 GB — but stops every running container.

**Original note, still applicable:** 12 GB free, and the image alone is 16 GB. Docker there
reports **185 GB of images with 81 GB reclaimable**. A `docker image prune` would likely free enough,
but that is a destructive change on a machine another team member is actively using — **ask before
touching it.** Reclaiming 81 GB would take the server to ~93 GB free, comfortably enough.

## Run plan, once unblocked

1. Clear server disk (needs sign-off from whoever owns the deployment).
2. `docker pull acorn421/san2patch` on the server (16 GB).
3. Add the Haiku 4.5 model entry via a patch file kept here.
4. Configure `.env` with `ANTHROPIC_API_KEY` (never commit it; `../.gitignore` covers `*/.env`).
5. **Reproduce 2–3 of their published cases first.** Good candidates from Table 1, all `correct`:
   `CVE-2017-14745` (binutils), `CVE-2017-7595` (libtiff), `CVE-2017-5969` (libxml2). If these do not
   come out as they report, our harness is wrong — stop and fix before running anything else.
6. Then the 12-case target set in `../server_snapshot/README.md`.
7. Normalize output to `../schema/baseline_result.schema.json` → `../results/san2patch/<batch>/`.

## Our side, for reference (server, refreshed 2026-08-13)

200 runs total (was 170; all 30 new ones are Java `baseline`). C/C++ unchanged at 83 runs over all
41 cases, but the scores improved after the gate-bug fixes landed:

| arm | runs | accepted | GT coverage | $/run |
|---|---|---|---|---|
| `baseline` | 41 | 41/41 | 0.913 (all 41 scored, was 0.900/36) | $0.39 |
| `hardening` | 42 | **39/42** (was 32/42) | **0.985** (was 0.961) | $2.10 |

Certified fixPOVs also went 19 → **41** after the merge, so every C/C++ case now has one.

Caveat unchanged: our `coverage_score` is fixPOV coverage, **not** their "repaired"
(which includes a functional-test gate we still lack). And per `../DATASETS_AND_INPUTS.md`, our
C/C++ alerts are hand-authored root-cause writeups — richer than the sanitizer log San2Patch gets —
so the arms are not yet input-comparable.


---

# How a run actually works

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
