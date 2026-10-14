#!/usr/bin/env bash
# Run San2Patch on a single VulnLoc case, on the server.
#
#   ./run_one.sh                      # default: CVE-2017-14745 (first VulnLoc case)
#   ./run_one.sh CVE-2016-1839        # any bug_id from vulnloc-meta-data.json
#   MODEL=gpt-4o ./run_one.sh         # override the model
#
# Architecture (why this is not just "python run.py"):
#   acorn421/san2patch is a Docker-in-Docker image. Its ENTRYPOINT starts an
#   inner dockerd, launches the AIM tracking stack, and runs the
#   acorn421/san2patch-benchmark container *inside* itself. The agent generates
#   patches in the outer container; every build / PoC replay / functional test
#   happens in the inner benchmark container. Hence --privileged.
#
# Run this ON THE SERVER (x86_64). It is not expected to work on an arm64 Mac:
# the image is amd64-only and ASan under emulation is unreliable.
set -euo pipefail

VULN_ID="${1:-CVE-2017-14745}"
MODEL="${MODEL:-claude-haiku-4.5}"
VERSION="${VERSION:-tot}"                 # tot = the paper's Tree-of-Thought config
EXP="${EXP:-autosec-$(echo "$VULN_ID" | tr '[:upper:].' '[:lower:]-')}"
CONTAINER="${CONTAINER:-san2patch}"

echo "=== San2Patch single-case run ==="
echo "  case       : $VULN_ID"
echo "  model      : $MODEL"
echo "  version    : $VERSION"
echo "  experiment : $EXP"
echo

# 1. Container up? (ENTRYPOINT does the DinD + benchmark-container bootstrap)
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "[!] container '$CONTAINER' is not running. Start it first with:"
  echo "    docker run -d --privileged --name $CONTAINER acorn421/san2patch:latest sleep infinity"
  exit 1
fi

# 2. The inner benchmark container must be up, or every validation step fails
#    in a way that looks like a patch failure rather than a harness failure.
if ! docker exec "$CONTAINER" docker ps --format '{{.Names}}' 2>/dev/null | grep -q san2patch-benchmark; then
  echo "[!] inner 'san2patch-benchmark' container is not running inside '$CONTAINER'."
  echo "    Check the entrypoint log:  docker logs $CONTAINER"
  exit 1
fi

# 3. Go.
echo "[→] starting run (this is the single long-running command)"
docker exec "$CONTAINER" bash -lc "
  cd /app && set -a && . ./.env && set +a &&
  python ./run.py Final run-patch \
    --vuln-ids '$VULN_ID' \
    --model '$MODEL' \
    --version '$VERSION' \
    --experiment-name '$EXP'
"

echo
echo "=== results ==="
echo "  in-container: /app/benchmarks/final/final-test/gen_diff_${EXP}/${VULN_ID}/"
echo "  copy out with:"
echo "    docker cp $CONTAINER:/app/benchmarks/final/final-test/gen_diff_${EXP} ./out/"
