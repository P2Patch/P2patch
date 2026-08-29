#!/usr/bin/env bash
# Pull the deployment's read-only run index into this directory.
#
# Read-only on both sides: it curls the dashboard API over SSH and writes here.
# Nothing is created or modified on the server. Re-run to refresh the snapshot.
#
# The server also has dashboard/export_static.py, which writes a full static tree
# (~53 MB) including per-run diffs, agent IO and logs. That WRITES to the server,
# so it is not what this script does — use it deliberately, not as a refresh.
set -euo pipefail
HOST="${AUTOSEC_HOST:?set AUTOSEC_HOST=user@host for the run host}"
KEY="${AUTOSEC_SSH_KEY:-$HOME/.ssh/id_ed25519}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for ep in runs stats; do
  ssh -i "$KEY" -o ConnectTimeout=15 "$HOST" "curl -s http://127.0.0.1:8000/api/$ep" > "$here/$ep.json"
  echo "[✓] $ep.json  ($(wc -c < "$here/$ep.json") bytes)"
done
