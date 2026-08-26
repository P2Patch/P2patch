#!/usr/bin/env bash
# Build the frontend and serve the whole dashboard from the backend on :8000.
# For hot-reload development, run the backend and `npm run dev` separately
# (see README.md).
set -euo pipefail

DASH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DASH_DIR/.." && pwd)"
VENV="$REPO_ROOT/.venv"
PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"

echo "==> Building frontend"
cd "$DASH_DIR/frontend"
[ -d node_modules ] || npm install
npm run build

echo "==> Preparing backend venv"
[ -d "$VENV" ] || python3 -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install -q -r "$DASH_DIR/backend/requirements.txt"

echo "==> Serving on http://$HOST:$PORT"
cd "$DASH_DIR/backend"
exec uvicorn app:app --host "$HOST" --port "$PORT"
