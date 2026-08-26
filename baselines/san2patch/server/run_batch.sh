#!/usr/bin/env bash
# Run San2Patch over the full VulnLoc set and capture everything for the paper.
#
#   bash run_batch.sh                          # claude-haiku-4.5, tot, all VulnLoc
#   MODEL=gpt-4o bash run_batch.sh             # another model, new batch dir
#   VULN_IDS=CVE-2017-5969 bash run_batch.sh   # a single case
#   WORKERS=2 bash run_batch.sh                # parallel cases (see caveat below)
#
# Detaches itself, so you can close the terminal. Progress:
#   tail -f /root/autosec-baselines/san2patch/runs/<batch>/run.log
#
# WHY A COLLECTOR: San2Patch writes its artifacts INSIDE the container, under
# /app/benchmarks/final/final-test/gen_diff_<exp>/. If the container is removed
# those are lost. This script mirrors them onto the server every SYNC_EVERY
# seconds and once more at the end, so a crash, an OOM or a docker rm cannot
# destroy a multi-hour run.
set -uo pipefail

MODEL="${MODEL:-claude-haiku-4.5}"
VERSION="${VERSION:-tot}"
VULN_IDS="${VULN_IDS:-vulnloc}"          # 'vulnloc' = the whole set
WORKERS="${WORKERS:-1}"
CONTAINER="${CONTAINER:-san2patch}"
SYNC_EVERY="${SYNC_EVERY:-300}"          # seconds between artifact syncs

ROOT="/root/autosec-baselines/san2patch"
BATCH="${BATCH:-$(echo "$MODEL" | tr -d '.' | tr '[:upper:]' '[:lower:]')-${VERSION}-$(date +%Y%m%d-%H%M)}"
OUT="$ROOT/runs/$BATCH"
CONTAINER_OUT="/app/benchmarks/final/final-test/gen_diff_${BATCH}"

mkdir -p "$OUT"
exec > >(tee -a "$OUT/run.log") 2>&1

echo "=== San2Patch batch: $BATCH ==="
echo "  model     : $MODEL"
echo "  version   : $VERSION"
echo "  vuln-ids  : $VULN_IDS"
echo "  workers   : $WORKERS"
echo "  output    : $OUT"
echo "  started   : $(date -Is)"
echo

# ---- preflight -------------------------------------------------------------
fail() { echo "[✗] $1"; exit 1; }
docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" || fail "container '$CONTAINER' not running"
docker exec "$CONTAINER" docker ps --format '{{.Names}}' 2>/dev/null | grep -q san2patch-benchmark \
  || fail "inner 'san2patch-benchmark' container not running (see: docker logs $CONTAINER)"
# The key the SELECTED model needs — checking only the Anthropic one meant a DeepSeek
# run passed preflight and then failed on its first call, minutes in.
case "$MODEL" in
  claude*)     NEEDED_KEY="ANTHROPIC_API_KEY" ;;
  deepseek*)   NEEDED_KEY="DEEPSEEK_API_KEY" ;;
  gpt*|o1*|o3*) NEEDED_KEY="OPENAI_API_KEY" ;;
  gemini*)     NEEDED_KEY="GOOGLE_API_KEY" ;;
  *)           NEEDED_KEY="" ;;
esac
if [ -n "$NEEDED_KEY" ]; then
  docker exec "$CONTAINER" bash -lc "grep -qE '^$NEEDED_KEY=.+' /app/.env" 2>/dev/null \
    || fail "$NEEDED_KEY is not set in /app/.env — $MODEL cannot run"
fi

# Which requested cases actually exist in the image? San2Patch dispatches by walking its
# vuln/ directory and intersecting with --vuln-ids, so an id with no vuln/<id>.json is
# never dispatched at all: no log line, no res.txt, no error. Batch 2 asked for 5 cases,
# ran 3, and reported "Patching completed" — the two missing ones left no trace anywhere.
# Four of run.py's own 43 VulnLoc ids are absent from the shipped image, which is why the
# paper's VulnLoc denominator is 39, not 43. Record the gap up front so it is a documented
# exclusion rather than a number that quietly fails to add up.
MISSING=""
PRESENT=""
if [ "$VULN_IDS" != "vulnloc" ]; then
  for c in ${VULN_IDS//,/ }; do
    if docker exec "$CONTAINER" test -f "/app/benchmarks/final/final-test/vuln/$c.json" 2>/dev/null
    then PRESENT="${PRESENT:+$PRESENT,}$c"
    else MISSING="${MISSING:+$MISSING,}$c"
    fi
  done
  if [ -n "$MISSING" ]; then
    echo "[!] NOT IN THE DATASET, will not run: $MISSING"
    echo "$MISSING" | tr ',' '\n' > "$OUT/missing_cases.txt"
  fi
  [ -n "$PRESENT" ] || { echo "[✗] none of the requested cases exist in the image"; exit 1; }
fi
echo "[✓] preflight passed"

# ---- provenance ------------------------------------------------------------
{
  echo "{"
  echo "  \"batch\": \"$BATCH\","
  echo "  \"baseline\": \"san2patch\","
  echo "  \"baseline_commit\": \"a8c5ace939cdf3de835fa50c617f4fe979f35e6d\","
  echo "  \"image_digest\": \"$(docker inspect --format '{{index .RepoDigests 0}}' acorn421/san2patch:latest 2>/dev/null)\","
  echo "  \"local_modifications\": \"0001-add-claude-haiku-4-5.patch (stock Anthropic model IDs are all retired)\","
  echo "  \"model\": \"$MODEL\","
  echo "  \"version\": \"$VERSION\","
  echo "  \"vuln_ids\": \"$VULN_IDS\","
  echo "  \"vuln_ids_present\": \"$PRESENT\","
  echo "  \"vuln_ids_missing_from_image\": \"$MISSING\","
  echo "  \"workers\": $WORKERS,"
  echo "  \"host\": \"$(hostname) $(uname -m) $(nproc)cores $(free -g | awk '/Mem:/{print $2}')GB\","
  echo "  \"load_at_start\": \"$(uptime | sed 's/.*load average: //')\","
  echo "  \"started_at\": \"$(date -Is)\""
  echo "}"
} > "$OUT/manifest.json"

# .env WITHOUT secrets — records dataset paths and tracing config for the paper
docker exec "$CONTAINER" bash -lc "sed -E 's/(KEY|TOKEN|SECRET)=.*/\1=<redacted>/' /app/.env" > "$OUT/env.txt" 2>/dev/null

# ---- usage proxy (token/cost metering, zero changes to their code) ---------
# langchain_anthropic honours ANTHROPIC_API_URL (verified: NOT ANTHROPIC_BASE_URL,
# which the raw SDK reads but LangChain overrides). Pointing it at a local proxy
# gets exact per-call token counts without editing a line of San2Patch.
# Only meaningful for Anthropic models; skipped otherwise.
# Which env var the client honours, and which host it talks to, differ per provider.
# LangChain's ChatAnthropic reads ANTHROPIC_API_URL; ChatOpenAI (which DeepSeek rides on)
# reads OPENAI_BASE_URL. Getting this wrong does not error — it silently bypasses the
# proxy and the run finishes with no token data at all, which is only discoverable
# afterwards, so the health check below treats a dead proxy as fatal to metering.
case "$MODEL" in
  claude*)    PROXY_UPSTREAM="https://api.anthropic.com"; PROXY_ENV="ANTHROPIC_API_URL" ;;
  deepseek*)  PROXY_UPSTREAM="https://api.deepseek.com";  PROXY_ENV="OPENAI_BASE_URL" ;;
  gpt*|o1*|o3*) PROXY_UPSTREAM="https://api.openai.com";  PROXY_ENV="OPENAI_BASE_URL" ;;
  *)          PROXY_UPSTREAM=""; PROXY_ENV="" ;;
esac

PROXY_PID=""
if [ -n "$PROXY_ENV" ] && [ "${PROXY:-1}" = "1" ]; then
  PROXY_PORT="${PROXY_PORT:-8788}"
  nohup python3 "$ROOT/usage_proxy.py" --out "$OUT/usage.jsonl" --port "$PROXY_PORT" \
    --upstream "$PROXY_UPSTREAM" > "$OUT/proxy.log" 2>&1 &
  PROXY_PID=$!
  sleep 2
  if curl -sf -I --max-time 5 "http://127.0.0.1:$PROXY_PORT/" >/dev/null 2>&1; then
    echo "[✓] usage proxy up on :$PROXY_PORT -> $PROXY_UPSTREAM (via \$$PROXY_ENV)"
    # Their code calls load_dotenv(override=True), so .env wins over the process env.
    # The var must therefore go INTO .env, not be passed with `docker exec -e`.
    docker exec "$CONTAINER" bash -lc "
      grep -v '^$PROXY_ENV=' /app/.env > /tmp/e && \
      echo '$PROXY_ENV=http://172.17.0.1:$PROXY_PORT' >> /tmp/e && mv /tmp/e /app/.env"
  else
    echo "[!] usage proxy failed health check — continuing WITHOUT token metering"
    kill $PROXY_PID 2>/dev/null; PROXY_PID=""
    docker exec "$CONTAINER" bash -lc "grep -v '^$PROXY_ENV=' /app/.env > /tmp/e && mv /tmp/e /app/.env" 2>/dev/null
  fi
fi

# ---- load sampler ----------------------------------------------------------
# This server is shared: the P2Patch pipeline runs Maven builds and Claude agents on
# it concurrently, and load has been observed anywhere from 2 to 9+ on 8 cores. Cost
# and outcomes do not care, but wall-clock does, and per-case time is a number we
# report. `load_at_start` in the manifest only characterises the batch's first moment,
# which is too coarse — contention arrives and leaves mid-batch. Sampling lets
# metrics.py attribute a mean load to each case's own window, so a timing can be
# qualified or excluded individually instead of writing off the whole batch.
( while true; do
    printf '{"ts":"%s","load1":%s,"cores":%s}\n' "$(date -Is)" \
      "$(cut -d' ' -f1 /proc/loadavg)" "$(nproc)" >> "$OUT/load.jsonl"
    sleep 30
  done ) &
LOAD_PID=$!

restore_env() {
  [ -n "${LOAD_PID:-}" ] && kill "$LOAD_PID" 2>/dev/null || true
  # Always unpoint the container from the proxy, or a later manual run would
  # silently fail against a dead endpoint.
  [ -n "${PROXY_ENV:-}" ] && docker exec "$CONTAINER" bash -lc \
    "grep -v '^$PROXY_ENV=' /app/.env > /tmp/e && mv /tmp/e /app/.env" 2>/dev/null || true
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
}

# ---- artifact collector ----------------------------------------------------
collect() {
  docker exec "$CONTAINER" bash -lc "[ -d '$CONTAINER_OUT' ]" 2>/dev/null || return 0
  rm -rf "$OUT/.gen_diff.tmp"
  docker cp "$CONTAINER:$CONTAINER_OUT" "$OUT/.gen_diff.tmp" >/dev/null 2>&1 || return 0
  rm -rf "$OUT/gen_diff" && mv "$OUT/.gen_diff.tmp" "$OUT/gen_diff"
  # summary.tsv: one row per case, straight from each res.txt
  { printf "case_id\tstatus\ttries\thas_patch\n"
    for d in "$OUT"/gen_diff/*/; do
      c=$(basename "$d"); [ -f "$d/res.txt" ] || continue
      st=$(grep -o 'code: [a-z_]*' "$d/res.txt" | tail -1 | cut -d' ' -f2)
      tr_=$(grep -c 'try:' "$d/res.txt")
      hp=$(ls "$d"/*success.diff >/dev/null 2>&1 && echo yes || echo no)
      printf "%s\t%s\t%s\t%s\n" "$c" "${st:-unknown}" "$tr_" "$hp"
    done
  } > "$OUT/summary.tsv"
}
( while true; do
    sleep "$SYNC_EVERY"
    collect
    # Watchdog: the proxy sits in the critical path, so revive it if it died.
    # Their invoke() already retries, which covers the gap while it comes back.
    if [ -n "$PROXY_PID" ] && ! kill -0 "$PROXY_PID" 2>/dev/null; then
      echo "[!] usage proxy died — restarting"
      nohup python3 "$ROOT/usage_proxy.py" --out "$OUT/usage.jsonl" --port "$PROXY_PORT" \
        --upstream "$PROXY_UPSTREAM" >> "$OUT/proxy.log" 2>&1 &
      PROXY_PID=$!
    fi
  done ) &
SYNC_PID=$!
trap 'kill $SYNC_PID 2>/dev/null; collect; restore_env' EXIT

# ---- the run ---------------------------------------------------------------
echo "[→] starting run at $(date -Is)"
# `docker exec` does NOT reliably return when run.py finishes. San2Patch initialises an
# Aim run per attempt, and Aim leaves a background child inside the container holding the
# exec session's stdout, so the client blocks on an EOF that never arrives. Batch 2
# completed all of its work at 11:47 and then sat in exactly this state for four hours,
# holding up every queued batch behind it — silently, because the batch looked "running".
#
# So we wait on run.py's own terminal marker instead of on the client's exit, and reap the
# client once it appears. Killing the client does not disturb anything inside the container:
# by then run.py has already written its results and exited.
docker exec "$CONTAINER" bash -lc "
  cd /app && set -a && . ./.env && set +a &&
  python ./run.py Final run-patch $WORKERS \
    --vuln-ids '$VULN_IDS' \
    --model '$MODEL' \
    --version '$VERSION' \
    --experiment-name '$BATCH'
" &
EXEC_PID=$!
RC=0
while kill -0 "$EXEC_PID" 2>/dev/null; do
  # An account usage limit does not fail the batch — it shreds it. Every remaining case
  # burns its 5 retries in about four seconds apiece and writes a res.txt that reads
  # exactly like a repair failure, so the run looks complete and is silently worthless.
  # We lost 12 cases to this before it was caught. Stop at the first sign and leave the
  # rest unrun, so `remaining` still knows they are outstanding.
  if grep -qE "specified API usage limits|credit balance is too low" "$OUT/run.log" 2>/dev/null; then
    echo "[✗] API USAGE LIMIT REACHED — aborting the batch so the remaining cases stay unrun"
    grep -m1 -oE "You will regain access on [^']*" "$OUT/run.log" 2>/dev/null | sed 's/^/    /'
    kill "$EXEC_PID" 2>/dev/null
    docker exec "$CONTAINER" bash -lc "pkill -f 'run.py Final'" 2>/dev/null || true
    RC=75   # EX_TEMPFAIL: retryable, and the chain checks for it
    break
  fi
  if grep -q "Patching completed for $BATCH" "$OUT/run.log" 2>/dev/null; then
    sleep 15                                  # let trailing output flush into the log
    if kill -0 "$EXEC_PID" 2>/dev/null; then
      echo "[i] run.py finished; reaping the docker exec client (Aim keeps it open)"
      kill "$EXEC_PID" 2>/dev/null
    fi
    break
  fi
  sleep 20
done
wait "$EXEC_PID" 2>/dev/null || RC=$?

kill $SYNC_PID 2>/dev/null
collect
restore_env
python3 "$ROOT/metrics.py" "$OUT" || true
echo
echo "=== triage: is every failure the tool's, or ours? ==="
python3 "$ROOT/triage.py" "$OUT"; TRIAGE_RC=$?
[ $TRIAGE_RC -ne 0 ] && echo "  ^^ RE-RUN THE FLAGGED CASES BEFORE REPORTING THIS BATCH"

python3 - "$OUT" <<'PY' 2>/dev/null || true
import json, sys, pathlib, datetime
out = pathlib.Path(sys.argv[1]); m = out / "manifest.json"
d = json.loads(m.read_text()); d["finished_at"] = datetime.datetime.now().astimezone().isoformat()
s = out / "summary.tsv"
if s.exists():
    rows = [l.split("\t") for l in s.read_text().splitlines()[1:] if l.strip()]
    d["cases"] = len(rows)
    counts = {}
    for r in rows: counts[r[1]] = counts.get(r[1], 0) + 1
    d["status_counts"] = counts
m.write_text(json.dumps(d, indent=2) + "\n")
PY

echo
echo "=== batch finished (exit $RC) at $(date -Is) ==="
[ -f "$OUT/summary.tsv" ] && { echo "--- status counts ---"; tail -n +2 "$OUT/summary.tsv" | cut -f2 | sort | uniq -c; }
echo "  artifacts: $OUT"
