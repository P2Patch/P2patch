# coreutils__coreutils_gnubug-25023_ca99c524e828 — gnubug-25023 (pr out-of-bounds read)

- **CWE:** CWE-125 (Out-of-bounds Read)
- **Advisory:** no GHSA/NVD entry (GNU bug tracker report); see
  https://debbugs.gnu.org/cgi/bugreport.cgi?bug=25023
- **Vulnerable version:** coreutils git `ca99c524e828cc1a1cfeff3cdfc5349f87143829`
- **Fix commit:** `d91aeef0527bf8ec0f83c3c3b69f3979c0b4c4a0`

## Root cause / sink

`pr` keeps its column separator as a `(pointer, length)` pair, `col_sep_string` /
`col_sep_length`. `-S<str>` sets both together in `separator_string()`:

```c
size_t len = strlen (optarg_S);   /* src/pr.c:850 */
if (INT_MAX < len) integer_overflow ();
col_sep_length = len;             /* src/pr.c:852 */
col_sep_string = optarg_S;        /* src/pr.c:853 */
```

`init_parameters()` then special-cases a literal-tab separator:

```c
else if (!join_lines && *col_sep_string == '\t')   /* src/pr.c:1237 (vulnerable) */
  col_sep_string = column_separator;               /* repoints at the 1-byte " " global */
```

This branch repoints `col_sep_string` at the global `column_separator`
(`static char *column_separator = (char *) " "`, src/pr.c:693) **without**
resetting `col_sep_length` — unlike the sibling `if` branch two lines above which
sets `col_sep_length = 1` alongside its own default-separator assignment. So a
separator that starts with `\t` and is longer than one byte desynchronizes the
pair: `col_sep_length` still names the real `-S` string's length while
`col_sep_string` points at a 1-byte buffer.

`print_sep_string()` then walks the stale length off the short buffer:

```c
char const *s = col_sep_string;   /* src/pr.c:2224 */
int l = col_sep_length;           /* src/pr.c:2225 */
...
while (l-- > 0) {
  if (*s == ' ') { ... }          /* src/pr.c:2241 -- reads past the 1-byte global */
```

The branch is only reached when `columns > 1` (e.g. `-m` merging >= 2 files, or a
`-2` two-column layout), so the repro needs multiple columns.

**Trust boundary:** the `-S` separator string, which on this codebase is
attacker-controlled (the pipeline's own alert drives `pr` with it); the missing
check is the `col_sep_length == 1` guard on the tab override.

## Path coverage

The finder alert's single trace (lines 852/853 → 1237 → 2225 → 2241) is the *only*
source-to-sink path: `separator_string()` → the `columns > 1` tab-override branch
in `init_parameters()` → `print_sep_string()`. The official fix changes exactly one
condition, `*col_sep_string == '\t'` → `col_sep_length == 1 && *col_sep_string == '\t'`,
which is the single behavior change a partial patch could fail to make. Coverage:

| POV | separator | length | before (pristine) | after (official fix) |
|---|---|---|---|---|
| `tab_separator_merge_columns` | `\t\t\t` | 3 | ASan global-buffer-overflow (reproduced) | runs cleanly (blocked) |
| `tab_prefix_mixed_separator` | `\tXX` | 3 | ASan global-buffer-overflow (reproduced) | runs cleanly (blocked) |

Two POVs deliberately, on the **technique** axis: the vulnerable condition keys
only on the *first byte* being `\t`, so both an all-tabs separator and a
tab-prefixed mixed separator reach the desync. `\tXX` (length 3) is the shortest
mixed separator that still crashes — a 2-byte separator (`\tX`) reads only `' '`
and the `'\0'` terminator of the 2-byte `" "` literal, i.e. stays in bounds, so it
would NOT reproduce; the OOB needs `col_sep_length >= 3`. A partial fix that
special-cased only all-tab separators (e.g. `strcmp (col_sep_string, "\t\t\t") == 0`)
would pass `tab_separator_merge_columns` yet still crash `tab_prefix_mixed_separator` —
both are needed to force the actual `col_sep_length == 1` fix. A single tab
(`-S$'\t'`, length 1) is the intended-override case (no bug, `col_sep_length` is
already 1), so it is deliberately not a POV.

## Official fix (the "after" oracle)

`official_fix.patch` is the literal upstream commit diff:

```diff
-      else if (!join_lines && *col_sep_string == '\t')
+      else if (!join_lines && col_sep_length == 1 && *col_sep_string == '\t')
         col_sep_string = column_separator;
```

It is `git apply`-able against the dataset source at the buggy commit and was
verified with `git apply --check` on the server.

## Build

`src/pr` is built with AddressSanitizer inside the project container. The dataset
source ships an empty `gnulib` submodule whose `.gitmodules` URL points at the
retired `git://git.sv.gnu.org/gnulib.git`, so the `build_command` first rewrites
the submodule URL in `.git/config` to the working HTTPS mirror (verified that
`git submodule init` preserves a pre-set URL) before running bootstrap/configure.

**Gnulib version skew (fixed 2026-08-20):** when the checkout the harness builds
from has an *empty* `gnulib/` (the common case -- a fresh worktree/mount shadows
whatever the Docker image baked in at `/workspace/repo`), `./bootstrap` used to be
run with no `--gnulib-srcdir`, so it fell back to its own internal git handling of
the `gnulib` submodule instead of an explicit, pinned `git submodule update --init`.
That desynchronized from the exact gnulib revision the tree's local overrides
(`gl/modules/*.diff`, in particular `gl/modules/tempname.diff`) were written
against, so `gnulib-tool --import` applied a newer/different gnulib and the diff's
hunks no longer matched context (`gnulib-tool: warning: module diacrit doesn't
exist` / `patch file gl/modules/tempname.diff didn't apply cleanly` / `./bootstrap:
gnulib-tool failed`). The fix: explicitly `git submodule update --init gnulib`
first -- this checks out the exact commit pinned by the superproject at
`ca99c524e828` (`6b26660a01125acb...`, verified reachable from
`git.savannah.gnu.org`) in about a second -- then run `./bootstrap --skip-po
--no-git --gnulib-srcdir=$PWD/gnulib` so bootstrap imports from that pinned
checkout instead of doing its own git-based fetch. When `gnulib/lib/*.c` is
already populated (e.g. reusing the image's baked-in tree), the submodule step is
skipped and bootstrap runs straight off `--gnulib-srcdir=$PWD/gnulib` with no
network dependency at all.

Two more fixes live in the `build_command`, mirroring the project Dockerfile:

1. The vendored gnulib (2016) predates glibc 2.28, which stopped exposing the
   libio internals it probes for. Without a compat step, `make` dies on
   `lib/freadseek.c:68 #error "Please port gnulib freadseek.c ..."`. The
   `sed -i 's/_IO_ftrylockfile/_IO_EOF_SEEN/g' lib/*.c` re-points the probe at
   the still-exported macro and re-supplies the flag macros at their glibc values
   via a `stdio-impl.h` append (this is what *this* POV set originally failed
   certification with — the manifest's `make -j1 src/pr` had no compat steps
   while the Dockerfile did; validation therefore errored on both sides until the
   build command was aligned).
2. `make -j"$(nproc)"` (full tree, not `make -j1 src/pr`): coreutils includes
   gnulib non-recursively, and the generated headers `src/pr.c` needs
   (`configmake.h`, `lib/getopt.h`, ...) are `BUILT_SOURCES` that automake only
   makes as part of `all`; a bare `src/pr` target on a fresh tree has no
   depfiles to pull them in implicitly.

```
git config submodule.gnulib.url https://git.savannah.gnu.org/git/gnulib.git && \
FORCE_UNSAFE_CONFIGURE=1 ./bootstrap --skip-po && \
sed -i 's/_IO_ftrylockfile/_IO_EOF_SEEN/g' lib/*.c && \
printf '#ifndef _IO_IN_BACKUP\n# define _IO_IN_BACKUP 0x0100\n#endif\n#ifndef _IO_NO_READS\n# define _IO_NO_READS 0x0004\n#endif\n#ifndef _IO_NO_WRITES\n# define _IO_NO_WRITES 0x0008\n#endif\n#ifndef _IO_CURRENTLY_PUTTING\n# define _IO_CURRENTLY_PUTTING 0x0800\n#endif\n' >> lib/stdio-impl.h && \
FORCE_UNSAFE_CONFIGURE=1 ./configure CFLAGS="-fsanitize=address -g -O0 -Wno-error -fcommon" \
  CXXFLAGS="-fsanitize=address -g -O0 -Wno-error -fcommon" \
  LDFLAGS="-fsanitize=address" && \
make -j"$(nproc)"
```

Writing the URL to `.git/config` (rather than editing the tracked `.gitmodules`)
leaves `git status` clean, so the POV staging never pollutes a persisted diff.

## Certification

```bash
python -m security_pipeline fixpov validate --project coreutils__coreutils_gnubug-25023_ca99c524e828
```
