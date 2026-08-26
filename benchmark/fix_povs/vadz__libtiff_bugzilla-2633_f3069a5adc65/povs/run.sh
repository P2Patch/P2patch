#!/usr/bin/env bash
# Ground-truth POV runner for vadz__libtiff_bugzilla-2633_f3069a5adc65 (bugzilla-2633).
#
# Drives the real tiff2ps CLI (built by setup_commands, at tools/tiff2ps in the
# repo root) against a crafted RGB+alpha TIFF fixture. PSDataColorContig()
# (tools/tiff2ps.c:2434) computes `es = samplesperpixel - nc` with no
# validation; for this fixture samplesperpixel == nc == 4 (RGB + alpha), so
# es == 0 and the alpha-matte adjustment `adjust = 255 - cp[nc];`
# (tools/tiff2ps.c:2470) reads one byte AHEAD of the current pixel -- on the
# final pixel of the row that is the byte just past the tf_bytesperrow-sized
# heap buffer tf_buf: a heap-buffer-overflow READ of size 1, caught by
# AddressSanitizer. The official fix (5ed9fea523316c2f5cec4d393e4d5d671c2dbc33)
# rejects the call up front with `if (es <= 0)`.
#
# Usage (from /workspace/repo, inside the project's Docker image):
#   bash .security-pipeline/gtpov/run.sh colorcontig_oob.tif
#
# Exit codes (same contract as ground_truth_povs):
#   0 -> vulnerability reproduced (AddressSanitizer crash seen)
#   1 -> blocked / did not reproduce
#   2 -> harness/build error (never 1 -- a broken harness must not look "blocked")
set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
poc="$script_dir/${1:?usage: run.sh <fixture.tif>}"
bin="./tools/tiff2ps"

if [ ! -x "$bin" ]; then
  echo "[gtpov] $bin not found -- build must run first" >&2
  exit 2
fi
if [ ! -f "$poc" ]; then
  echo "[gtpov] PoC file missing: $poc" >&2
  exit 2
fi

export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=0}"

out="$($bin "$poc" 2>&1)"

if echo "$out" | grep -q "SUMMARY: AddressSanitizer:"; then
  echo "[gtpov] reproduced: AddressSanitizer crash" >&2
  exit 0
fi

echo "[gtpov] did not reproduce" >&2
echo "$out" >&2
exit 1