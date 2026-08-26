#!/usr/bin/env bash
# Residual-gap POV runner for vadz__libtiff_bugzilla-2611_9a72a69e035e.
#
# These are OJPEG integer divide-by-zeros that the 2016 `decoder_ok` fix
# (43bc256d, the ground-truth CVE-2016-10267 fix) does NOT reach, and that
# upstream only closed years later. They therefore reproduce BOTH on the
# unpatched tree AND with official_fix.patch applied -- the residual contract.
#
#   r1_readheader  OJPEGReadHeaderInfo: sp->strile_length % (subsampling_ver*8)
#                  (tif_ojpeg.c:1079) with YCbCrSubsampling vertical factor 0.
#                  Closed upstream only in 4.1.0 commit 43908ce15e8b
#                  ("OJPEG: fix integer division by zero on corrupted
#                  subsampling factors").
#
# Exit codes (residual contract, same as ground truth):
#   0 -> reproduced (gap still open -- expected for both unpatched and official-fix)
#   1 -> blocked (a stronger-than-upstream patch closed it)
#   2 -> harness/build error (never 1 -- a broken harness must not look "blocked")
set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
mode="${1:-r1_readheader}"

export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1}"

# Build the libtiff public-API driver against the static libtiff.a produced by
# setup_commands (./configure --enable-static). Any compile/link failure maps to
# exit 2 (harness error), never to 1 (blocked).
build_driver() {
  local bin="$1"
  local src="$script_dir/ojpeg_scanline.c"
  local liba="./libtiff/.libs/libtiff.a"
  if [ ! -f "$liba" ]; then
    echo "[respov] static libtiff.a not found at $liba -- setup_commands must build it" >&2
    return 2
  fi
  # System libs libtiff itself needs (jpeg/z/lzma/...) come from the generated
  # tools/Makefile; add a safety-net set too (duplicate -l flags are harmless).
  local sys_libs=""
  if [ -f tools/Makefile ]; then
    sys_libs="$(sed -n 's/^LIBS = //p' tools/Makefile | head -1)"
  fi
  if ! cc -fsanitize=integer-divide-by-zero -fcommon -g -O0 \
        -I./libtiff "$src" "$liba" $sys_libs -ljpeg -lz -llzma -lm \
        -o "$bin" 2> "$bin.compile.log"; then
    echo "[respov] driver compile/link failed:" >&2
    cat "$bin.compile.log" >&2
    return 2
  fi
  return 0
}

run_scanline_pov() {
  local fixture="$1"; local nreads="$2"; local site="$3"
  local poc="$script_dir/$fixture"
  if [ ! -f "$poc" ]; then
    echo "[respov] fixture missing: $poc" >&2
    exit 2
  fi
  local bin="/tmp/respov_ojpeg_scanline_$$"
  build_driver "$bin" || exit 2

  out="$("$bin" "$poc" "$nreads" 2>&1)"; rc=$?

  if echo "$out" | grep -q "division by zero"; then
    echo "[respov] reproduced: UBSan division-by-zero ($site)" >&2
    echo "$out" >&2
    exit 0
  fi
  if [ "$rc" -eq 136 ]; then
    echo "[respov] reproduced: SIGFPE (hardware divide-by-zero trap) ($site)" >&2
    echo "$out" >&2
    exit 0
  fi
  echo "[respov] did not reproduce ($site) rc=$rc" >&2
  echo "$out" >&2
  exit 1
}

case "$mode" in
  r1_readheader)
    run_scanline_pov "poc_r1_ojpeg_readheader_subsampling.tif" 1 \
      "OJPEGReadHeaderInfo strile_length % (subsampling_ver*8), tif_ojpeg.c:1079"
    ;;
  *)
    echo "[respov] unknown mode: $mode" >&2
    exit 2
    ;;
esac
