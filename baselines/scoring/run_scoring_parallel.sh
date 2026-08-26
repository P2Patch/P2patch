#!/usr/bin/env bash
# Re-score every San2Patch patch against the CURRENT POV manifests, N projects at a time.
#
# The sequential `run_scoring.sh` exists because `_ReplayCheckout` reuses ONE
# reconstruction checkout per project, so two cases of the same project must not
# run at once. That constraint is per-project, not global — and in this dataset
# almost every case IS its own project slug (libtiff CVE-2017-7599 and CVE-2017-7600
# are different slugs at different revisions), so partitioning by slug recovers
# nearly all the available parallelism without ever putting two workers in the same
# checkout.
#
# One worker per slug runs fixpov THEN respov for that slug. Both families in the
# same worker on purpose: they share the project's checkout and its warm ASan build
# output, so the second family is an incremental rebuild instead of a second cold
# one — and it makes the per-project replay lock uncontended rather than merely safe.
#
# JOBS defaults to 3. The box has 8 cores and also runs the live pipeline; those runs
# are LLM-latency-bound rather than CPU-bound, but 3 concurrent ASan builds is already
# most of what is left. Raise it only after looking at `uptime`.
#
# Usage:
#   setsid nohup bash baselines/scoring/run_scoring_parallel.sh > scoring.log 2>&1 < /dev/null &
#   JOBS=2 bash baselines/scoring/run_scoring_parallel.sh          # gentler
set -uo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
PY="${PY:-/root/autosec/.venv/bin/python}"
W="${W:-$ROOT/replay_work}"
JOBS="${JOBS:-3}"
# Cold ASan builds under 3-way contention take longer than the 900s default, and a
# timeout is recorded as `errored` — an unmeasured case, which is the outcome this
# whole pass exists to eliminate.
CMD_TIMEOUT="${CMD_TIMEOUT:-1800}"
BUILD_TIMEOUT="${BUILD_TIMEOUT:-3600}"

cd "$ROOT"
mkdir -p "$W" "$ROOT/scoring_logs"

echo "############ parallel scoring  jobs=$JOBS  $(date -u +%FT%TZ) ############"
echo "root=$ROOT  runs-dir=$W"
"$PY" - <<'PY'
import sys
from pathlib import Path
bench = Path("baselines/vendor/san2patch-benchmark")
if not bench.is_dir():
    sys.stderr.write(
        "\n!! %s is missing. Every case's base commit will read UNKNOWN, which looks\n"
        "!! exactly like 'the bases agree' — and the two zziplib cases that need an\n"
        "!! alternate base will fail again. Run `cd baselines && ./setup.sh san2patch-benchmark`.\n\n"
        % bench
    )
    raise SystemExit(1)
PY
[ $? -ne 0 ] && exit 1

# Which slugs have anything to score, across both families. --force so the plan is
# "everything scoreable", not "everything not yet scored".
#
# SLUGS=<file> overrides the plan. The reason to want that is resumption: the CPU
# budget on this box is shared with the live pipeline, so the right JOBS is a
# judgement call that can change mid-pass, and re-planning from scratch after a
# restart would re-score (with --force) everything already finished. Pass the
# remainder instead.
slugs_file="$W/slugs.txt"
if [ -n "${SLUGS:-}" ]; then
  cp "$SLUGS" "$slugs_file"
  echo "using caller-supplied slug list: $SLUGS"
else
  : > "$slugs_file"
  for family in fixpov respov; do
    "$PY" baselines/score_patches.py san2patch --family "$family" --force --dry-run \
      | sed -nE 's/^ *would score [^ ]+ +-> ([^ ]+).*/\1/p'
  done | sort -u > "$slugs_file"
fi

total=$(wc -l < "$slugs_file")
echo "projects to score: $total"
[ "$total" -eq 0 ] && { echo "nothing to do"; exit 0; }
cat "$slugs_file"

score_one() {
  slug="$1"
  log="$ROOT/scoring_logs/$slug.log"
  echo ">>> START $slug  $(date -u +%T)"
  for family in fixpov respov; do
    "$PY" baselines/score_patches.py san2patch --family "$family" --project "$slug" \
      --force --no-rollup --runs-dir "$W" \
      --command-timeout-seconds "$CMD_TIMEOUT" --build-timeout-seconds "$BUILD_TIMEOUT" \
      >> "$log" 2>&1
  done
  echo "<<< DONE  $slug  $(date -u +%T)  rc=$?  ($log)"
}
export -f score_one
export ROOT PY W CMD_TIMEOUT BUILD_TIMEOUT

xargs -a "$slugs_file" -P "$JOBS" -I{} bash -c 'score_one "$@"' _ {}

echo "############ rebuilding roll-up  $(date -u +%FT%TZ) ############"
# No --project and no --force: every case is now scored, so this pass skips them all
# and loads each summary from disk, producing a roll-up covering the whole set.
"$PY" baselines/score_patches.py san2patch --family both --runs-dir "$W"
"$PY" baselines/pov_report.py --out baselines/POV_SCORES.md

echo "############ ALL DONE $(date -u +%FT%TZ) ############"
