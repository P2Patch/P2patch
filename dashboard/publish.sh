#!/usr/bin/env bash
# Refresh the published dashboard snapshot.
#
#   dashboard/publish.sh              # re-export the static API (fetches fix diffs)
#   dashboard/publish.sh --no-diffs   # skip the GitHub fix-diff fetch (offline)
#   dashboard/publish.sh --build      # also produce a local static build to preview
#
# Then commit the regenerated tree and push — Vercel redeploys automatically:
#   git add dashboard/frontend/public/api && git commit -m "Refresh dashboard snapshot" && git push
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FRONTEND="$SCRIPT_DIR/frontend"

# Prefer the repo venv (has httpx/fastapi); fall back to whatever python is on PATH.
if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
  PY="$REPO_ROOT/.venv/bin/python"
else
  PY="$(command -v python3 || command -v python)"
fi

DO_BUILD=0
EXPORT_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --build) DO_BUILD=1 ;;
    *) EXPORT_ARGS+=("$arg") ;;
  esac
done

echo "→ Exporting static API snapshot (python: $PY)"
( cd "$REPO_ROOT" && "$PY" dashboard/export_static.py "${EXPORT_ARGS[@]+"${EXPORT_ARGS[@]}"}" )

if [[ "$DO_BUILD" == "1" ]]; then
  echo "→ Building the published frontend (vite --mode static)"
  ( cd "$FRONTEND" && npm run build:static )
  echo "→ Preview locally (a plain static server mirrors the host; vite preview would"
  echo "   proxy /api to the absent backend):"
  echo "     python3 -m http.server 4455 --directory dashboard/frontend/dist"
  echo "   then open http://localhost:4455"
fi

cat <<'EOF'

✓ Snapshot refreshed at dashboard/frontend/public/api

Next:
  git add dashboard/frontend/public/api
  git commit -m "Refresh dashboard snapshot"
  git push
  # Vercel rebuilds and redeploys the public dashboard automatically.
EOF
