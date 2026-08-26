#!/usr/bin/env bash
# Clone (or re-pin) every third-party baseline listed in pins.json into vendor/.
#
# vendor/ is gitignored: the clones are nested git repos, one of them ships with
# no license, and none of them belong in our history. Everything that comes back
# out of a baseline run is normalized into results/ instead.
#
#   ./setup.sh              # clone/checkout every baseline at its pin
#   ./setup.sh san2patch    # just one
#   VERIFY=1 ./setup.sh     # don't clone; just report drift from the pins
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
vendor="$here/vendor"
pins="$here/pins.json"
want="${1:-}"

mkdir -p "$vendor"

# key<TAB>url<TAB>commit  — stdlib python only, same rule as security_pipeline/
python3 - "$pins" "$want" <<'PY' | while IFS=$'\t' read -r key url commit; do
import json, sys
pins, want = sys.argv[1], sys.argv[2]
data = json.load(open(pins))["baselines"]
for k, v in data.items():
    if want and k != want:
        continue
    print(f"{k}\t{v['url']}\t{v['commit']}")
PY
  dest="$vendor/$key"

  if [ -n "${VERIFY:-}" ]; then
    if [ ! -d "$dest/.git" ]; then
      echo "[✗] $key — not cloned"
      continue
    fi
    at="$(git -C "$dest" rev-parse HEAD)"
    if [ "$at" = "$commit" ]; then
      echo "[✓] $key @ ${commit:0:12}"
    else
      echo "[!] $key DRIFTED: at ${at:0:12}, pinned ${commit:0:12}"
    fi
    continue
  fi

  if [ ! -d "$dest/.git" ]; then
    echo "[→] cloning $key from $url"
    git clone --quiet "$url" "$dest"
  fi

  echo "[→] $key: checking out ${commit:0:12}"
  git -C "$dest" fetch --quiet origin "$commit" 2>/dev/null || git -C "$dest" fetch --quiet origin
  git -C "$dest" checkout --quiet --detach "$commit"
  echo "[✓] $key @ ${commit:0:12}"
done

echo
echo "vendor/ is gitignored. Publishable output goes to baselines/results/ only."
