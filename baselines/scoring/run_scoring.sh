#!/usr/bin/env bash
# Score every baseline tool's patches against our certified POV manifests.
#
# Sequential on purpose: _ReplayCheckout reuses ONE reconstruction checkout per
# project (that is what keeps a 13-case project from paying for 13 cold builds),
# so two concurrent replays of the same project would race on rmtree/create. The
# CLI holds a per-project lock, but serializing here means we never wait on it.
set -uo pipefail
cd /root/autosec-cmp
PY=/root/autosec/.venv/bin/python
# Reconstruction checkouts live on /, which has 228G free. The Docker volume is at
# 91% and every project image already exists, so builds are cache hits and grow it
# by nothing -- but the checkouts themselves (binutils is ~2GB) must not land there.
W=/root/autosec-cmp/replay_work

for arm in "san2patch fixpov" "san2patch respov" "loop_repair fixpov" "loop_repair respov"; do
  set -- $arm
  echo "############ $1 / $2  $(date -u +%H:%M:%S) ############"
  $PY baselines/score_patches.py "$1" --family "$2" --runs-dir "$W"
  echo "rc=$?"
done
echo "############ ALL DONE $(date -u +%H:%M:%S) ############"
