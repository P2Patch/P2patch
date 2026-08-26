# Deployment snapshot — which projects to run the baselines on

Read-only snapshot of the deployment's run index, pulled 2026-08-12 with `./fetch.sh`.
Temporary: it exists to pick the baseline-comparison target set, not to be a permanent artifact.

## Accessing the dashboard

**http://2.28.1.51:8000**

- `uvicorn app:app --host 0.0.0.0 --port 8000`, run by `autosec-dashboard.service` as user
  `secpipeline` from `/root/autosec/dashboard/backend`.
- **No reverse proxy, no TLS, no custom domain, and `ufw` is inactive** — nginx/caddy/apache/traefik
  are all absent or stopped, so port 8000 is exposed directly to the internet over plain HTTP.
  `2.28.1.51` reverse-resolves only to Hetzner's generic `static.51.1.28.2.clients.your-server.de`,
  which also works as `http://static.51.1.28.2.clients.your-server.de:8000`. If a real domain is
  pointed at this box, it is configured at the DNS provider, not on the server.
- Server repo is at `dc660d8` (ahead of us — includes the C/C++ ground-truth POV batch).
  `security_pipeline_runs/` there is **27 GB / 171 run dirs**.

## What is already done — the headline

**Every one of the 41 C/C++ cases has already been run**, on both arms. The "which projects should
we run first" question is largely already answered; what is left is deciding where a baseline
comparison is worth the compute.

| arm | runs | accepted | mean GT coverage | $/run | min/run |
|---|---|---|---|---|---|
| `baseline` (alert-only) | 41 | **41 / 41** | 0.900 (n=36) | **$0.39** | 5.3 |
| `hardening` | 42 | 32 / 42 | 0.961 (n=28) | $2.20 | 27.5 |

170 runs total (83 C/C++, 87 Java), 154 accepted. Model is `claude-haiku-4-5` for 163 of them.
**Total C/C++ spend: $108.47 across 83 runs, $1.31 mean.**

### Cost, against what the papers report

| system | $/case | our comparable |
|---|---|---|
| LoopRepair (gpt-4o-mini) | $0.074 | — |
| **our `baseline` arm (haiku-4.5)** | **$0.39** | — |
| San2Patch (gpt-4o) | $0.48 | we are **19% cheaper** |
| PatchAgent (Haiku→Opus range) | $0.10–$2.15 | our `hardening` $2.20 ≈ their Opus |
| PatchAgent 5-model union (the 92.13% headline) | $6.11 | 5.6× our hardening arm |

Our cheap arm is already cost-competitive with San2Patch while scoring 0.900 mean ground-truth
coverage. That is the strongest number in this snapshot.

## Where we plausibly beat them — run the baselines here first

Cases where a paper reports its own failure and our ground-truth coverage is 1.00:

| case | project | San2Patch | PatchAgent | ours |
|---|---|---|---|---|
| CVE-2018-8964 | libming | **incorrect (all tests)** | not in their set | 1.00 |
| CVE-2016-8691 | jasper | **incorrect (all tests)** | ● full | 1.00 |
| CVE-2017-15232 | libjpeg | **incorrect (all tests)** | ● full | 1.00 |
| CVE-2013-7437 | potrace | incorrect (some tests) | not in their set | 1.00 |
| CVE-2016-1839 | libxml2 | incorrect (some tests) | ● full | 1.00 |

**Use-after-free is the standout opportunity.** San2Patch reports **0/2 on UAF** and says so
explicitly; LoopRepair repairs 1/2. Both UAF cases are ours: CVE-2018-8964 (we score 1.00) and
CVE-2018-8806 (0.67). PatchAgent claims 86.96% on temporal errors but neither libming case is in
its published table. This is the cleanest place to show a real difference.

## Where we would lose — run these to know the honest number

Ten `hardening` runs were rejected, and the binutils cluster is the worrying one because the papers
report success on exactly these:

| case | our failure | San2Patch | PatchAgent |
|---|---|---|---|
| CVE-2017-15025 | POV not blocked in 3 corrections | correct | ● full |
| CVE-2017-14745 | POV not blocked in 3 corrections | correct | not in set |
| CVE-2017-15020 | POV not blocked; also `unable_to_patch` | alternative | not in set |
| bugzilla-2611 | POV not blocked in 3 corrections | alternative | ● full |

Plus two at coverage **0.00** — CVE-2016-1833 (libxml2) and CVE-2022-4645 (libtiff) — though both
are CrashRepair "RED-TEAM" cases absent from PatchAgent's and San2Patch's tables, so only LoopRepair
has a number to compare against.

Three of the ten rejections are **scaffold, not patch defects** and should not count against us:
`harden stage crashed: PermissionError` (CVE-2022-4645), `no JSON object found` (CVE-2013-7437),
and two `exploiter did not produce a reproducing POV` (CVE-2016-1833, CVE-2016-10092).

## Two caveats before any of this becomes a claim

1. **`coverage_score` is not their "repaired".** Ours is ground-truth POV coverage — did the patch
   block the real CVE exploit. Theirs is compile ∧ PoC blocked ∧ **functional tests pass**. We still
   have no functional tests on C/C++ (`test_command = true` everywhere), so our 100% accept rate on
   the `baseline` arm is not yet comparable to a repair rate. Porting `san2patch-benchmark`'s
   `test_func.sh` remains the gate on every number here.
2. **Coverage 1.00 on 31 of 36 scored baseline runs is suspiciously uniform.** Either the arm is
   genuinely strong or the metric is not discriminating on these cases. Worth one manual audit of a
   1.00 patch against the developer fix before leaning on it — `PIPELINE_ANALYSIS_v4` found patches
   that passed our gates and were still exploitable.

## Suggested target set

Twelve cases, ~$25 per baseline at our observed rates:

- **Beat-them candidates (5):** CVE-2018-8964, CVE-2016-8691, CVE-2017-15232, CVE-2013-7437, CVE-2016-1839
- **Lose-to-them candidates (4):** CVE-2017-15025, CVE-2017-14745, CVE-2017-15020, bugzilla-2611
- **UAF pair (1 more):** CVE-2018-8806
- **Both papers ● and we are 1.00 — the control (2):** CVE-2017-5969, CVE-2016-5314

Deliberately balanced: a set of only our wins measures nothing.

## Files

| file | what |
|---|---|
| `runs.json` | `/api/runs` — 170 run summaries (status, profile, model, cost, coverage/residual scores) |
| `stats.json` | `/api/stats` — aggregate counts by status and CWE |
| `fetch.sh` | re-pull both, read-only over SSH |

Per-run detail (diffs, agent IO, docker logs) is **not** here — it is 53 MB as a static export and
27 GB in raw artifacts. Pull individual runs from `http://2.28.1.51:8000/api/runs/<run_id>` as needed.
