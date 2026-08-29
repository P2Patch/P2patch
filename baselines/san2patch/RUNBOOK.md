# San2Patch runbook — running the benchmark with a new model

Everything needed to reproduce the VulnLoc evaluation, or to run it again with a different
model (DeepSeek, GPT-4o, Gemini …). Written so the whole thing is four commands once the
model is registered.

Server: `$SAN2PATCH_HOST` (e.g. `root@<run-host>`), harness at `/root/autosec-baselines/san2patch/`.
Scripts are version-controlled at `baselines/san2patch/server/` — **edit them there and
copy up**, never edit only on the server.

---

## TL;DR — run the whole benchmark with a new model

```bash
ssh "$SAN2PATCH_HOST"
cd /root/autosec-baselines/san2patch

# 1. register the model (idempotent, verifies against the CLI)
docker cp add_model.py san2patch:/tmp/
docker exec san2patch python3 /tmp/add_model.py deepseek-chat

# 2. put its key in the container's .env
docker exec san2patch bash -lc "echo 'DEEPSEEK_API_KEY=sk-...' >> /app/.env"

# 3. sanity-check the machine
bash healthcheck.sh

# 4. run everything, gated and detached
MODEL=deepseek-chat bash batches.sh chain-remaining

# results
python3 aggregate.py runs --model deepseek-chat --out aggregate-deepseek
```

`chain-remaining` is model-aware: it only counts batches whose manifest records the model
you asked for, so a DeepSeek run does not think Haiku's 34 successes are already done.

---

## Before you start

**Copy the current scripts up** if the repo has moved on:

```bash
cd <repo>/baselines/san2patch/server
for f in *.sh *.py; do
  scp -i ~/.ssh/<key> $f "$SAN2PATCH_HOST":/root/autosec-baselines/san2patch/$f.new
done
ssh "$SAN2PATCH_HOST" 'cd /root/autosec-baselines/san2patch && for f in *.new; do mv $f ${f%.new}; done && chmod +x *.sh *.py'
```

The `.new` + `mv` is not decoration: **bash reads a script incrementally**, so `scp`ing over
`run_batch.sh` while a batch is executing it corrupts the running batch. `mv` is an atomic
rename and leaves the running process on its original inode.

**Check the containers.** `healthcheck.sh` covers this, but the failure that matters is the
*inner* `san2patch-benchmark` container — the outer one can be up while the inner is dead,
and then every case fails in setup. `docker restart san2patch && sleep 60` fixes it.

---

## Registering a model

All four stock Anthropic model ids in this image are **retired**, which is why
`claude-haiku-4.5` had to be added at all (`0001-add-claude-haiku-4-5.patch`). Expect the
OpenAI and Gemini ids to retire the same way. `add_model.py` handles anything reachable
through an existing Patcher class:

```bash
docker exec san2patch python3 /tmp/add_model.py --list          # what is registered now
docker exec san2patch python3 /tmp/add_model.py deepseek-chat   # add one
```

It edits by anchor string (not line number), refuses to double-apply, and **verifies by
asking the CLI whether it now accepts the model** rather than trusting its own edits.

A provider that is not OpenAI-, Anthropic- or Google-compatible needs a new Patcher class
first; `add_model.py`'s `DEEPSEEK_CLASSES` block is the template — DeepSeek needed only a
different `base_url` and key because it speaks the OpenAI wire format.

### Known risk with any non-Anthropic model

San2Patch drives every stage through LangChain structured output
(`with_structured_output`). Claude Haiku 4.5 failed this **twice in ~275 calls**. A model
with weaker function-calling will fail more, and **their code counts a validation failure
as a failed try** — so a structured-output problem looks like a low repair rate, not like
an integration bug. Check after the first batch:

```bash
grep -c "validation error" runs/<batch>/run.log     # healthy: 0-2
```

If it is high, the run is measuring JSON compliance, not repair ability. Say so rather than
reporting the number.

---

## Cost and time metering

`run_batch.sh` starts a local proxy and points the container at it through `/app/.env`, so
**San2Patch's own code is unmodified** — it persists no token accounting of its own.

| model prefix | upstream | env var the client honours |
|---|---|---|
| `claude*` | api.anthropic.com | `ANTHROPIC_API_URL` |
| `deepseek*` | api.deepseek.com | `OPENAI_BASE_URL` |
| `gpt*`, `o1*`, `o3*` | api.openai.com | `OPENAI_BASE_URL` |

Two traps, both learned the hard way:

- It must go **into `/app/.env`**, not `docker exec -e`, because their code calls
  `load_dotenv(override=True)` — the file beats the process environment.
- LangChain honours `ANTHROPIC_API_URL`, **not** `ANTHROPIC_BASE_URL` (which the raw SDK
  reads but LangChain overrides). Getting it wrong does not error: it silently bypasses the
  proxy and the run finishes with no token data at all.

Add the model's price to `PRICES` in `metrics.py` or cost comes back null with a
`cost_note` — deliberately loud rather than a wrong `$0`.

---

## Monitoring a run

```bash
tail -f runs/<batch>/run.log                         # live
bash batches.sh status                               # what is running / finished
tail -f runs/chain-*.log                             # group transitions + healthchecks
```

The chain is detached with `setsid`, so **closing your laptop does not stop it**. Between
groups it re-runs `healthcheck.sh`, attempts a reclaim if blocked, and stops loudly rather
than continuing into a wall.

---

## Reading the results

```bash
python3 aggregate.py runs --model <model> --out aggregate-<model>
```

**Use `aggregate.tsv`, never `res.txt` or `summary.tsv` directly.** The `validity` column is
the point: a case that never reached the model still writes a `res.txt` reading
`vuln_test_failed`, indistinguishable from a real failure. Computing a success rate from the
raw files gave **26/39** where the true answer was **34/39**.

Validity is decided by **whether tokens were actually spent**, not by what `res.txt` claims.

| column | meaning |
|---|---|
| `validity` | `valid` = a real result · `needs_rerun` = never reached the model |
| `status` | `success` · `vuln_test_failed` · `patch_failed` · `build_failed` |
| `tries` | 1–5; San2Patch retries up to 5 times and halts on first success |
| `contended` | `True` = timed under load > 70 % of cores; exclude from timing claims |
| `mean_load` | load averaged over this case's own window |

---

## Failure modes, and what each looks like

| symptom | verdict | what to do |
|---|---|---|
| case "fails" in ~4 s, 5 tries, **0 tokens** | `api_limit` | raise the limit, re-run. The batch aborts itself (rc=75) so later cases stay unrun |
| batch finished its work but never exits | — | Aim holds the `docker exec` open; `run_batch.sh` reaps it automatically now |
| case requested but no log line at all | — | not in the image; check `missing_cases.txt` and `manifest.json` |
| every case dies in setup | `harness` | inner container is down: `docker restart san2patch && sleep 60` |
| `Connection error..` in the log | `proxy_suspect` | metering proxy died; the watchdog restarts it within one sync interval |
| timings much worse than usual | check `contended` | the server is shared with the P2Patch pipeline; outcomes and cost are unaffected |

`triage.py` assigns these automatically and runs at the end of every batch. It exits
non-zero when anything needs a re-run.

---

## Dataset facts you must not re-derive

- **The denominator is 39, not 43.** `bugchrom-1404`, `CVE-2017-9992`, `CVE-2016-3186`,
  `CVE-2016-5314` are in `run.py`'s vulnloc list but ship **no dataset files**, so they are
  never dispatched and leave no trace. 43 − 4 = 39 matches the paper exactly.
- **`CVE-2017-14745` has no `src/` tree** and fails in setup every time (~10 min, ~$0.73).
  It is in `KNOWN_BROKEN` and skipped by `chain-remaining`. To fix it properly, run that
  case's own `config.sh`/`build.sh` inside the benchmark container to populate `src/`.
- **Retries are 5 by default** (`--retry-cnt`), halting on first success. A failure costs
  ~4× a success because it exhausts all five.

---

## Adding a whole new baseline

Make a sibling directory (`/root/autosec-baselines/patchagent/`) with the same
`runs/<batch>/` shape. The layout exists so a later comparison script can walk
`*/runs/*/aggregate.tsv` without knowing anything about the individual tools.
