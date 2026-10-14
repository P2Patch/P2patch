#!/usr/bin/env bash
# Ground-truth POV runner for vadz__libtiff_bugzilla-2611_9a72a69e035e (bugzilla-2611,
# CWE-369 divide-by-zero in OJPEGDecodeRaw).
#
# Drives the REAL libtiff OJPEG decoder through the CLI tool named in the
# original bug report (`tiffmedian`; the report typos it as "tiffmedia") against
# the canonical upstream reproducer: the 416-byte BigTIFF-mutated OJPEG file
# from Agostino Sarubbo's fuzz corpus (asarubbo/poc 00083-libtiff-fpe-OJPEGDecodeRaw).
#
# Mechanism: OJPEGPreDecode() fails partway through (OJPEGReadHeaderInfo errors
# out on the malformed embedded JPEG stream) and OJPEGDecode() is still invoked
# by TIFFReadScanline for the first raster row. OJPEGDecode dispatches straight
# into OJPEGDecodeRaw() with no check that pre-decode ever completed, so codec
# state left at its zero-initialized value -- bytes_per_line == 0 -- is used as
# the divisor:
#   if (cc%sp->bytes_per_line!=0)          tif_ojpeg.c:816
# with cc = tif_scanlinesize = 3 (1x1 RGB). The project is built with
# -fsanitize=integer-divide-by-zero, so the trap is observable as the UBSan
# "runtime error: division by zero" report (we force halt_on_error=1 so the
# process aborts at the trap and the outcome is deterministic). With the
# official fix applied (OJPEGDecode early-exits when OJPEGPreDecode failed,
# "Cannot decode: decoder not correctly initialized"), no division ever runs
# and tiffmedian exits cleanly.
#
# Usage (from /workspace/repo, inside the project's Docker image):
#   bash .security-pipeline/gtpov/run.sh
#
# Exit codes (ground-truth contract):
#   0 -> vulnerability reproduced (UBSan division-by-zero report seen)
#   1 -> blocked / did not reproduce
#   2 -> harness/build error (never 1 -- a broken harness must not look "blocked")
#
# Two POV modes select the same OJPEGDecodeRaw `cc % bytes_per_line` (line 816)
# divide-by-zero sink through different front doors:
#   (default / "tiffmedian") the tiffmedian CLI from the original bug report.
#   "libapi"                 a small libtiff public-API driver: TIFFOpen then
#                            TIFFReadScanline(row 0) TWICE. The first read fails
#                            in OJPEGReadHeaderInfo, but TIFFStartStrip already
#                            set tif_curstrip, so the second read of the same row
#                            has strip==tif_curstrip, TIFFSeek skips the refill /
#                            predecode, and OJPEGDecode is reached with the
#                            zero-initialized bytes_per_line -> 3 % 0. Decouples
#                            the POV from the tiffmedian tool.
# Both are blocked by the official decoder_ok fix (OJPEGDecode early-exits).
set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
poc="$script_dir/poc_00083_ojpeg_fpe.tif"
mode="${1:-tiffmedian}"

export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1}"

if [ ! -f "$poc" ]; then
  echo "[gtpov] PoC fixture missing: $poc" >&2
  exit 2
fi

run_tiffmedian() {
  tiffmedian_bin="./tools/tiffmedian"
  if [ ! -x "$tiffmedian_bin" ]; then
    echo "[gtpov] tiffmedian binary not found at $tiffmedian_bin -- setup_commands must build it" >&2
    exit 2
  fi
  out="$("$tiffmedian_bin" "$poc" "${poc}.out.tif" 2>&1)"
  rc=$?

  if echo "$out" | grep -q "division by zero"; then
    echo "[gtpov] reproduced: UBSan division-by-zero inside OJPEGDecodeRaw" >&2
    echo "$out" >&2
    exit 0
  fi

  # Fallback: on the unpatched build the modulo is also a hardware idiv, so if
  # the UBSan check were ever missing from a setup variant, the SIGFPE (128+8)
  # still proves the vulnerable divide ran. The fixed build never divides here.
  if [ "$rc" -eq 136 ]; then
    echo "[gtpov] reproduced: SIGFPE (hardware divide-by-zero trap) in tiffmedian" >&2
    echo "$out" >&2
    exit 0
  fi

  echo "[gtpov] did not reproduce (tiffmedian rc=$rc)" >&2
  echo "$out" >&2
  exit 1
}

run_libapi() {
  # Build the libtiff public-API driver against the static libtiff.a produced by
  # setup_commands. Any compile/link failure maps to exit 2, never 1 (blocked).
  src="$script_dir/ojpeg_scanline.c"
  liba="./libtiff/.libs/libtiff.a"
  bin="/tmp/gtpov_ojpeg_scanline_$$"
  if [ ! -f "$liba" ]; then
    echo "[gtpov] static libtiff.a not found at $liba -- setup_commands must build it" >&2
    exit 2
  fi
  sys_libs=""
  if [ -f tools/Makefile ]; then
    sys_libs="$(sed -n 's/^LIBS = //p' tools/Makefile | head -1)"
  fi
  if ! cc -fsanitize=integer-divide-by-zero -fcommon -g -O0 \
        -I./libtiff "$src" "$liba" $sys_libs -ljpeg -lz -llzma -lm \
        -o "$bin" 2> "$bin.compile.log"; then
    echo "[gtpov] driver compile/link failed:" >&2
    cat "$bin.compile.log" >&2
    exit 2
  fi
  # Two reads of row 0: the second hits OJPEGDecode via the stale tif_curstrip.
  out="$("$bin" "$poc" 2 2>&1)"
  rc=$?

  if echo "$out" | grep -q "division by zero"; then
    echo "[gtpov] reproduced: UBSan division-by-zero inside OJPEGDecodeRaw (libapi)" >&2
    echo "$out" >&2
    exit 0
  fi
  if [ "$rc" -eq 136 ]; then
    echo "[gtpov] reproduced: SIGFPE (hardware divide-by-zero trap) (libapi)" >&2
    echo "$out" >&2
    exit 0
  fi
  echo "[gtpov] did not reproduce (libapi rc=$rc)" >&2
  echo "$out" >&2
  exit 1
}

case "$mode" in
  tiffmedian) run_tiffmedian ;;
  libapi)     run_libapi ;;
  *) echo "[gtpov] unknown mode: $mode" >&2; exit 2 ;;
esac