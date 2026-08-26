#!/usr/bin/env bash
# Run the VulnLoc set in fixed batches of 5, one batch per invocation.
#
#   bash batches.sh list          # show every batch and its cases
#   bash batches.sh run 1         # launch batch 1, detached; returns immediately
#   bash batches.sh chain 3 4 5 6 # run those batches back-to-back, detached, gated
#   bash batches.sh status        # what is running / what has finished
#
# WHY BATCHES AND NOT ONE 43-CASE RUN: each case drives an inner container through a
# full build + sanitizer test cycle, so a long run accumulates image layers and build
# output on the volume. Stopping every 5 cases gives a place to check disk and load
# *before* committing the next hour, and caps the blast radius of a bad batch — a
# wedged inner container costs 5 cases, not 43.
#
# DETACHMENT IS THE POINT: `setsid` puts the batch in its own session, so it survives
# the SSH connection dropping (a laptop lid closing, a network change). Nothing about
# the run depends on the operator staying connected.
set -uo pipefail

ROOT="/root/autosec-baselines/san2patch"
SIZE="${SIZE:-5}"
MODEL="${MODEL:-claude-haiku-4.5}"
# Filesystem-safe form, used in batch directory names.
MSLUG=$(echo "$MODEL" | tr -cd '[:alnum:].-' | tr -d '.' | tr '[:upper:]' '[:lower:]')

# The paper's VulnLoc set, in run.py's own order (do not re-sort — keeping their order
# makes our per-case results line up with theirs without a mapping step).
CASES=(
  CVE-2017-14745 CVE-2017-15020 CVE-2017-15025 CVE-2017-6965  gnubug-19784
  gnubug-25003   gnubug-25023   gnubug-26545   bugchrom-1404  CVE-2017-9992
  CVE-2016-8691  CVE-2016-9557  CVE-2016-5844  CVE-2012-2806  CVE-2017-15232
  CVE-2018-14498 CVE-2018-19664 CVE-2016-9264  CVE-2018-8806  CVE-2018-8964
  bugzilla-2611  bugzilla-2633  CVE-2016-10092 CVE-2016-10094 CVE-2016-10272
  CVE-2016-3186  CVE-2016-5314  CVE-2016-5321  CVE-2016-9273  CVE-2016-9532
  CVE-2017-5225  CVE-2017-7595  CVE-2017-7599  CVE-2017-7600  CVE-2017-7601
  CVE-2012-5134  CVE-2016-1838  CVE-2016-1839  CVE-2017-5969  CVE-2013-7437
  CVE-2017-5974  CVE-2017-5975  CVE-2017-5976
)
# Present in run.py's vulnloc list but NOT shipped in the image — no vuln/<id>.json, so
# San2Patch never dispatches them and they leave no trace. 43 - 4 = 39, which is exactly
# the VulnLoc denominator the paper reports (31/39), so these are their exclusions too,
# not a broken install on our side. Verified with:
#   docker exec san2patch ls /app/benchmarks/final/final-test/vuln/
MISSING_FROM_IMAGE=(bugchrom-1404 CVE-2017-9992 CVE-2016-3186 CVE-2016-5314)

is_missing() { for m in "${MISSING_FROM_IMAGE[@]}"; do [ "$m" = "$1" ] && return 0; done; return 1; }

TOTAL=${#CASES[@]}
NBATCH=$(( (TOTAL + SIZE - 1) / SIZE ))

# Cases with no recorded result in any batch so far. This is the honest basis for
# "what is left": it survives a wedged batch, a batch that ran fewer cases than it was
# given, and re-runs — none of which a fixed batch number would notice.
# Its src/ tree is absent from the image, so every attempt dies in setup. Kept out of
# re-runs (it costs ~10 min and $0.73 to fail identically) but its recorded result stays,
# as a documented harness exclusion rather than a silent gap.
KNOWN_BROKEN=(CVE-2017-14745)
is_broken() { for m in "${KNOWN_BROKEN[@]}"; do [ "$m" = "$1" ] && return 0; done; return 1; }

# Batch dirs belonging to the CURRENT model, by what their manifest records rather than
# by directory name. Without this, starting a DeepSeek run would see Haiku's 34 successes
# and conclude there was nothing left to do — the failure mode being an empty run that
# looks like a completed one.
model_batches() {
  for m in "$ROOT"/runs/*/manifest.json; do
    [ -f "$m" ] || continue
    grep -q "\"model\": \"$MODEL\"" "$m" && dirname "$m"
  done
}

remaining_cases() {
  local done_ids rerun_ids
  done_ids=$(for b in $(model_batches); do
               for d in "$b"/gen_diff/*/; do
                 [ -f "$d/res.txt" ] && basename "$d"
               done; done 2>/dev/null | sort -u)
  # A case can have a res.txt and still be outstanding: an API-limit casualty writes one
  # that reads exactly like a repair failure. aggregate.py decides validity by whether
  # tokens were actually spent, so ask it rather than trusting the file's existence.
  python3 "$ROOT/aggregate.py" "$ROOT/runs" >/dev/null 2>&1 || true
  rerun_ids=$(python3 -c "
import json,sys
try: print('\n'.join(json.load(open('$ROOT/runs/aggregate.json'))['summary']['needs_rerun_ids']))
except Exception: pass" 2>/dev/null)
  for c in "${CASES[@]}"; do
    is_missing "$c" && continue
    is_broken "$c" && continue
    if grep -qx "$c" <<<"$rerun_ids"; then echo "$c"; continue; fi
    grep -qx "$c" <<<"$done_ids" || echo "$c"
  done
}

slice() {  # $1 = 1-based batch number -> comma-separated ids
  local n=$1 start=$(( ($1 - 1) * SIZE )) out=""
  for ((i = start; i < start + SIZE && i < TOTAL; i++)); do
    out="${out:+$out,}${CASES[$i]}"
  done
  echo "$out"
}

case "${1:-list}" in

list)
  echo "$TOTAL cases, $NBATCH batches of $SIZE"
  for ((b = 1; b <= NBATCH; b++)); do printf "  batch %-2s  %s\n" "$b" "$(slice "$b")"; done
  ;;

run|runsync)
  MODE="$1"
  B="${2:?usage: batches.sh run <batch-number>}"
  [ "$B" -ge 1 ] && [ "$B" -le "$NBATCH" ] || { echo "batch must be 1..$NBATCH"; exit 1; }
  IDS="$(slice "$B")"

  if pgrep -f "run_batch.sh" >/dev/null; then
    echo "[✗] a batch is already running — wait for it, or kill it first:"
    pgrep -af "run_batch.sh"; exit 1
  fi

  BATCH="b$(printf '%02d' "$B")-${MSLUG}-tot-$(date +%Y%m%d-%H%M)"
  OUT="$ROOT/runs/$BATCH"
  mkdir -p "$OUT"

  # Disk snapshot BEFORE, so per-batch growth is measurable rather than inferred.
  # /var/lib/containerd is a bind-mount of the data volume, which is where images
  # actually live — the root filesystem's free space is not the constraint here.
  { echo "{"
    echo "  \"batch_number\": $B,"
    echo "  \"cases\": \"$IDS\","
    echo "  \"volume_avail_before\": \"$(df -h --output=avail /var/lib/containerd | tail -1 | tr -d ' ')\","
    echo "  \"volume_used_pct_before\": \"$(df -h --output=pcent /var/lib/containerd | tail -1 | tr -d ' ')\","
    echo "  \"docker_images_size_before\": \"$(docker system df --format '{{.Size}}' 2>/dev/null | head -1)\","
    echo "  \"load_before\": \"$(uptime | sed 's/.*load average: //')\""
    echo "}"
  } > "$OUT/batch_env.json"

  echo "=== launching batch $B/$NBATCH ==="
  echo "  cases  : $IDS"
  echo "  output : $OUT"
  if [ "$MODE" = "runsync" ]; then
    # Foreground: the chain needs to know when this batch is actually done.
    env MODEL="$MODEL" BATCH="$BATCH" VULN_IDS="$IDS" bash "$ROOT/run_batch.sh" > "$OUT/nohup.out" 2>&1
    echo "  done   : $OUT (exit $?)"
  else
    # setsid + nohup: survives this SSH session ending.
    setsid nohup env MODEL="$MODEL" BATCH="$BATCH" VULN_IDS="$IDS" \
      bash "$ROOT/run_batch.sh" > "$OUT/nohup.out" 2>&1 < /dev/null &
    sleep 5
    echo "  pid    : $(pgrep -f "run_batch.sh" | head -1)"
    echo "  watch  : tail -f $OUT/run.log"
  fi
  ;;

remaining)
  R=$(remaining_cases)
  n=$(echo "$R" | grep -c . || true)
  echo "$n case(s) with no result yet:"
  echo "$R" | sed 's/^/  /'
  echo
  echo "excluded (absent from the image, never dispatchable): ${MISSING_FROM_IMAGE[*]}"
  ;;

chain-remaining)
  # Chain over what is actually left, in groups of SIZE. Preferred over `chain <n>...`
  # after anything has gone wrong, because it re-derives the work from results on disk
  # instead of assuming every earlier batch ran every case it was handed.
  mapfile -t REM < <(remaining_cases)
  [ ${#REM[@]} -gt 0 ] || { echo "nothing left to run"; exit 0; }
  # NOT `GROUPS` — that is a special read-only bash array (the caller's group ids);
  # assigning to it fails and takes the whole command down with it.
  CHUNKS=()
  for ((i = 0; i < ${#REM[@]}; i += SIZE)); do
    g=""; for ((j = i; j < i + SIZE && j < ${#REM[@]}; j++)); do g="${g:+$g,}${REM[$j]}"; done
    CHUNKS+=("$g")
  done
  LOG="$ROOT/runs/chain-$(date +%Y%m%d-%H%M).log"
  echo "=== chaining ${#REM[@]} remaining case(s) in ${#CHUNKS[@]} group(s) ==="
  printf '  %s\n' "${CHUNKS[@]}"
  setsid nohup bash -c '
    ROOT="'"$ROOT"'"
    # Injected the same way as ROOT: the body is single-quoted, so anything not spliced
    # in here is empty inside the chain — which would name every batch dir "g01--tot-..."
    # and, worse, launch run_batch.sh on its default model instead of the chosen one.
    MODEL="'"$MODEL"'"
    MSLUG="'"$MSLUG"'"
    # pgrep -f matches against the FULL command line, and this shell'"'"'s own command
    # line contains the path to run_batch.sh — so a naive `while pgrep -f run_batch.sh`
    # matches itself and waits forever. It did: the first chain-remaining sat in this
    # loop indefinitely with nothing else running. Exclude our own pid.
    other_batch_running() { pgrep -f "$ROOT/run_batch.sh" | grep -vx "$$" | grep -q .; }
    while other_batch_running; do
      echo "[…] waiting for an in-flight batch ($(date -Is))"; sleep 60
    done
    i=0
    for ids in '"$(printf '%q ' "${CHUNKS[@]}")"'; do
      i=$((i+1))
      echo; echo "=== chain: healthcheck before group $i ($(date -Is)) ==="
      if ! bash "$ROOT/healthcheck.sh"; then
        bash "$ROOT/healthcheck.sh" --reclaim >/dev/null 2>&1
        if ! bash "$ROOT/healthcheck.sh"; then
          echo "[✗] still blocked after reclaim — stopping at group $i."; exit 1
        fi
      fi
      echo "=== chain: group $i — $ids ($(date -Is)) ==="
      B="g$(printf "%02d" $i)-${MSLUG}-tot-$(date +%Y%m%d-%H%M)"
      mkdir -p "$ROOT/runs/$B"
      env MODEL="$MODEL" BATCH="$B" VULN_IDS="$ids" bash "$ROOT/run_batch.sh" \
        > "$ROOT/runs/$B/nohup.out" 2>&1
      rc=$?
      # run_batch.sh tees its own stdout to run.log, so this redirect captures the same
      # bytes a second time — 536KB of exact duplication across a full benchmark. Keep it
      # only when it holds something run.log does not (a failure before the tee is set up).
      cmp -s "$ROOT/runs/$B/run.log" "$ROOT/runs/$B/nohup.out" 2>/dev/null \
        && rm -f "$ROOT/runs/$B/nohup.out"
      # 75 = the batch hit an account usage limit. Continuing would destroy every
      # remaining group the same way, in seconds, so the chain stops here and the
      # untouched cases stay outstanding for a later `chain-remaining`.
      if [ $rc -eq 75 ]; then
        echo "[✗] API usage limit — stopping the chain at group $i; later groups NOT started."
        exit 75
      fi
      [ $rc -ne 0 ] && echo "[!] group $i exited non-zero (rc=$rc)"
    done
    echo; echo "=== chain complete $(date -Is) ==="
  ' > "$LOG" 2>&1 < /dev/null &
  sleep 2
  echo "  log   : $LOG"
  ;;

chain)
  shift
  [ $# -gt 0 ] || { echo "usage: batches.sh chain <n> [n...]"; exit 2; }
  LIST="$*"
  LOG="$ROOT/runs/chain-$(date +%Y%m%d-%H%M).log"

  # The whole chain detaches once, so the sequencing between batches lives on the
  # server. Driving it from a laptop over SSH would stall the queue the moment the
  # connection dropped — the batches would each survive (setsid), but nothing would
  # start the next one.
  setsid nohup bash -c '
    ROOT="'"$ROOT"'"
    echo "=== chain: batches '"$LIST"' — started $(date -Is) ==="
    # A batch already in flight (started separately) must finish first, or the
    # next run would be refused by the already-running guard and be silently lost.
    while pgrep -f run_batch.sh >/dev/null; do
      echo "[…] waiting for the in-flight batch to finish ($(date -Is))"; sleep 60
    done
    for n in '"$LIST"'; do
      echo
      echo "=== chain: healthcheck before batch $n ($(date -Is)) ==="
      if ! bash "$ROOT/healthcheck.sh"; then
        echo "[!] healthcheck reported a BLOCKING issue — attempting reclaim"
        bash "$ROOT/healthcheck.sh" --reclaim >/dev/null 2>&1
        if ! bash "$ROOT/healthcheck.sh"; then
          echo "[✗] still blocked after reclaim — stopping the chain at batch $n."
          echo "    Batches before this one are complete and valid."
          exit 1
        fi
        echo "[✓] reclaim cleared it — continuing"
      fi
      echo "=== chain: batch $n ($(date -Is)) ==="
      bash "$ROOT/batches.sh" runsync "$n" || echo "[!] batch $n exited non-zero — continuing to the next"
    done
    echo
    echo "=== chain complete $(date -Is) ==="
  ' > "$LOG" 2>&1 < /dev/null &
  sleep 2
  echo "=== chain launched: batches $LIST ==="
  echo "  log   : $LOG"
  echo "  watch : tail -f $LOG"
  ;;

status)
  if pgrep -f "run_batch.sh" >/dev/null; then
    echo "RUNNING:"; pgrep -af "run_batch.sh" | sed 's/^/  /'
  else
    echo "no batch running"
  fi
  echo
  for d in "$ROOT"/runs/*/; do
    [ -d "$d" ] || continue
    n=$(basename "$d")
    fin=$(grep -c "batch finished" "$d/run.log" 2>/dev/null || echo 0)
    ok=$(tail -n +2 "$d/summary.tsv" 2>/dev/null | wc -l)
    printf "  %-38s %s  cases_with_result=%s\n" "$n" \
      "$([ "$fin" -gt 0 ] && echo FINISHED || echo in-progress)" "$ok"
  done
  ;;

*) echo "usage: batches.sh {list|run <n>|status}"; exit 2 ;;
esac
