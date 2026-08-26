#!/usr/bin/env bash
# Is the server fit to run the NEXT batch? One command, answered from evidence.
#
#   bash healthcheck.sh            # report
#   bash healthcheck.sh --reclaim  # also prune what is provably safe to prune
#
# Checks, in the order that actually gates a run:
#   1. Volume free space  — images and build output live on /dev/sdb, NOT on /.
#                           `df /` looks healthy while the volume is full.
#   2. Docker reclaimable — build cache is the fastest-growing and safest thing to drop.
#   3. Both containers    — outer `san2patch` and the inner `san2patch-benchmark` it
#                           spawns; the inner one is the one that silently dies.
#   4. Load / RAM         — timing numbers are only comparable on an idle machine, and
#                           a contended batch has to be excluded from the paper later.
#   5. Stray proxies      — a leftover usage_proxy from a killed batch holds port 8788
#                           and would make the next batch's health check fail.
set -uo pipefail

RECLAIM=0; [ "${1:-}" = "--reclaim" ] && RECLAIM=1
ROOT="/root/autosec-baselines/san2patch"
warn=0; block=0

hdr() { printf "\n\033[1m%s\033[0m\n" "$1"; }
ok()   { printf "  [\033[32m✓\033[0m] %s\n" "$1"; }
wrn()  { printf "  [\033[33m!\033[0m] %s\n" "$1"; warn=$((warn+1)); }
bad()  { printf "  [\033[31m✗\033[0m] %s\n" "$1"; block=$((block+1)); }

hdr "1. disk (the volume is what matters — images live on /dev/sdb)"
AVAIL_G=$(df -BG --output=avail /var/lib/containerd | tail -1 | tr -dc '0-9')
PCT=$(df --output=pcent /var/lib/containerd | tail -1 | tr -dc '0-9')
df -h /var/lib/containerd / | sed 's/^/      /'
# Headroom rule of thumb, from measured batches: a 5-case batch's images + build output
# have cost well under 10 GB, so 40 GB is several batches of margin, and 20 GB is one.
if   [ "$AVAIL_G" -lt 20 ]; then bad  "only ${AVAIL_G}G free (${PCT}% used) — reclaim before the next batch"
elif [ "$AVAIL_G" -lt 40 ]; then wrn  "${AVAIL_G}G free (${PCT}% used) — enough for ~1 batch; reclaim soon"
else                             ok   "${AVAIL_G}G free (${PCT}% used)"
fi

hdr "2. docker reclaimable"
docker system df | sed 's/^/      /'
CACHE=$(docker system df --format '{{.Type}}\t{{.Reclaimable}}' 2>/dev/null | awk -F'\t' '/Build Cache/{print $2}')
echo "      build cache reclaimable: ${CACHE:-unknown}"
if [ "$RECLAIM" = "1" ]; then
  echo "      pruning build cache + dangling images (never touches a tagged image or"
  echo "      a running container, so no benchmark project can be lost)..."
  docker builder prune -af 2>&1 | tail -2 | sed 's/^/      /'
  docker image prune -f  2>&1 | tail -1 | sed 's/^/      /'
  echo "      after: $(df -h --output=avail /var/lib/containerd | tail -1 | tr -d ' ') free"
fi

hdr "3. containers"
if docker ps --format '{{.Names}}' | grep -qx san2patch; then
  ok "outer 'san2patch' up ($(docker ps --filter name=^san2patch$ --format '{{.Status}}'))"
  if docker exec san2patch docker ps --format '{{.Names}}' 2>/dev/null | grep -q san2patch-benchmark; then
    ok "inner 'san2patch-benchmark' up"
  else
    bad "inner 'san2patch-benchmark' NOT running — the next batch would fail preflight"
    echo "      fix: docker restart san2patch && sleep 60"
  fi
else
  bad "outer 'san2patch' NOT running   (fix: docker start san2patch)"
fi

hdr "4. load / memory"
uptime | sed 's/^/      /'
free -h | sed 's/^/      /'
L1=$(uptime | sed 's/.*load average: //' | cut -d, -f1 | tr -d ' ')
CORES=$(nproc)
# Timing is a reported number in the paper, so contention is a correctness issue here,
# not just a speed one.
awk -v l="$L1" -v c="$CORES" 'BEGIN{exit !(l > c*0.7)}' \
  && wrn "load ${L1} on ${CORES} cores — per-case timings from this batch will be inflated" \
  || ok  "load ${L1} on ${CORES} cores — timings will be trustworthy"

hdr "5. stray processes from a previous batch"
# Anchored to an ACTUAL invocation. A bare `-f run_batch.sh` also matches the chain
# driver, whose command line merely mentions the path — which dumped the entire chain
# script into this report and could bury a real blocking result under it.
BATCHPAT="^bash $(dirname "$0")/run_batch.sh"
if pgrep -f "$BATCHPAT" >/dev/null; then
  wrn "a batch is still running:"; pgrep -af "$BATCHPAT" | sed 's/^/      /'
else ok "no batch running"; fi
if pgrep -f usage_proxy.py >/dev/null; then
  wrn "orphaned usage_proxy (holds :8788, would break the next batch's metering):"
  pgrep -af usage_proxy.py | sed 's/^/      /'
  echo "      fix: pkill -f usage_proxy.py"
else ok "no orphaned usage proxy"; fi

hdr "verdict"
if   [ "$block" -gt 0 ]; then echo "  NOT READY — $block blocking issue(s) above"; exit 1
elif [ "$warn"  -gt 0 ]; then echo "  READY, with $warn warning(s) — read them before starting"; exit 0
else echo "  READY for the next batch"; exit 0; fi
