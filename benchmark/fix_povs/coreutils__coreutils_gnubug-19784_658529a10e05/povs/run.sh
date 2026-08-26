#!/usr/bin/env bash
# Ground-truth POV runner for coreutils__coreutils_gnubug-19784_658529a10e05
# (gnubug-19784, CWE-125).
#
# Drives the real `src/make-prime-list` binary (built by the manifest
# build_command with -fsanitize=address) — the build-time host tool that
# generates src/primes.h from an odd-prime sieve. main() allocates a `size`-byte
# sieve (`size = (limit-1)/2`, sieve[i] represents 3+2i) and scans it with
#
#     while (i < size && sieve[++i] == 0)
#
# The guard bounds-checks i's *pre-increment* value, but the array access is
# indexed with the *post-increment* value of the same expression, so when the
# scan reaches i == size-1 the guard passes, ++i makes i == size, and
# sieve[size] reads one byte past the heap buffer. Because every index after
# the last odd prime is sieved to zero, the scan always walks off the end this
# way (the last sieve slot holds the largest odd prime <= limit; if THAT is at
# size-1 the OOB happens there, otherwise the trailing-zero walk still reaches
# it) -- the read is unconditional for any limit >= 3.
#
# Usage (from /workspace/repo, inside the project's Docker image):
#   bash .security-pipeline/gtpov/run.sh <mode>   # mode = 5000 | 5001 | 3
#
# Exit codes (ground-truth contract):
#   0 -> vulnerability reproduced (ASan heap-buffer-overflow in make-prime-list)
#   1 -> blocked / did not reproduce
#   2 -> harness/build error (never 1 -- a broken harness must not look "blocked")
set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
bin="./src/make-prime-list"

if [ ! -x "$bin" ]; then
  echo "[gtpov] src/make-prime-list not built -- build_command must run first" >&2
  exit 2
fi

mode="${1:-5000}"
case "$mode" in
  5000|5001|3) limit="$mode" ;;
  *)
    echo "[gtpov] unknown mode: $mode (expect 5000|5001|3)" >&2
    exit 2
    ;;
esac

export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0}"
export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

out="$("$bin" "$limit" 2>&1)"
status=$?

if printf '%s' "$out" | grep -q "heap-buffer-overflow"; then
  echo "[gtpov] reproduced: ASan heap-buffer-overflow in make-prime-list (limit=$limit)" >&2
  exit 0
fi

echo "[gtpov] did not reproduce (make-prime-list exit=$status, limit=$limit)" >&2
printf '%s\n' "$out" >&2
exit 1