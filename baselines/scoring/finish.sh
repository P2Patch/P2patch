#!/usr/bin/env bash
# Wait for the scoring run to finish, then render the report — so the result is
# ready whether or not anyone is connected when it lands.
#
# A SEPARATE script rather than an extra line in run_scoring.sh: bash reads a script
# incrementally as it executes, so editing the running one can make it resume at a
# byte offset that is now the middle of a different line.
set -uo pipefail
cd /root/autosec-cmp
until grep -q "ALL DONE" scoring.log 2>/dev/null; do
  pgrep -f "bash run_scoring.sh" >/dev/null || { echo "scoring process gone before ALL DONE"; break; }
  sleep 30
done
/root/autosec/.venv/bin/python baselines/pov_report.py --out baselines/POV_SCORES.md
echo "REPORT READY $(date -u +%H:%M:%S)"
