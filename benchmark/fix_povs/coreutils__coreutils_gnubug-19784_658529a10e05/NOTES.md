# coreutils__coreutils_gnubug-19784_658529a10e05 — gnubug-19784 (make-prime-list out-of-bounds read)

- **CWE:** CWE-125 (Out-of-bounds Read)
- **Advisory:** no GHSA/NVD entry (GNU bug tracker report); see
  https://debbugs.gnu.org/cgi/bugreport.cgi?bug=19784
- **Vulnerable version:** coreutils git `658529a10e05d06524d5f591a08f04c04159b4cc`
- **Fix commit:** `1d0f1b7ce10807290715d0b7c4637ac9d4fc7821` ("build: ensure
  make-prime-list doesn't access out of bounds memory", by Yury Usishchev /
  Pádraig Brady, 2015-02-05)

## What the bug is

`src/make-prime-list.c` is coreutils' **build-time host tool**: it generates
`src/primes.h` (the odd-prime table used by `factor`/`expr`). It is not an
installed end-user binary — it runs during the build (`make`'s `GEN src/primes.h`
rule), which is exactly how the bug was found: building coreutils with
`CFLAGS=-fsanitize=address` crashed inside `make`:

```
  GEN      src/primes.h
==12657== ERROR: AddressSanitizer: heap-buffer-overflow
```

It also explains why the bug lived for so long — the `-fsanitize=address` CI
pass associated with v8.22-75-gf940fec did not regenerate `src/primes.h` (no
`make clean`), so `make-prime-list` simply never ran under ASan.

## Root cause / sink

```c
size = (limit-1)/2;              /* make-prime-list.c:196, sieve[i] = 3+2i */
sieve = xalloc (size);           /* make-prime-list.c:198 — size-byte heap buffer */
...
for (i = 0; i < size;)
  {
    unsigned p = 3+2*i;
    process_prime (&prime_list[nprimes++], p);
    for (j = (p*p - 3)/2; j < size; j+= p)
      sieve[j] = 0;
    while (i < size && sieve[++i] == 0)   /* make-prime-list.c:214 — THE BUG */
      ;
  }
```

The sieve-scan loop `while (i < size && sieve[++i] == 0)` bounds-checks `i`'s
**pre-increment** value (`i < size`) but indexes the array with the
**post-increment** value of the same expression (`sieve[++i]`, where `++i`
evaluates first, making the index `i+1`). When the scan reaches `i == size-1`
the guard passes (`size-1 < size`), `++i` makes `i == size`, and `sieve[size]`
is read one byte past the `size`-byte allocation. The reporter's words: "When
'i' reaches 'size-1' it gets incremented and then (unallocated) memory is
accessed."

The OOB read is **unconditional for any `limit >= 3`**, in one of two shapes:

1. The largest odd `<= limit` is at the outermost slot `size-1` (limit odd and
   prime, e.g. 4999): the scan guard passes with `i = size-1` and immediately
   reads `sieve[size]`.
2. Otherwise (limit composite, e.g. 5001): every slot past the last prime is
   sieved to zero, so `sieve[++i] == 0` keeps the guard passing — `i` advances
   to `size-1` on zeros, passes `i < size` once more, and reads `sieve[size]`.

`limit < 3` returns early (make-prime-list.c:189-190) without allocating, so
there the bug is not reachable.

**Trust boundary:** the `LIMIT` command-line argument (the only input the tool
takes) sizes the sieve; a "complete fix" must make the scan stop before
`sieve[size]` for every limit. The finder alert frames it as the alert's single
source-to-sink trace: `xalloc(size)` at line 198 → the mis-guarded index at
line 214.

## Path coverage

The vulnerability is one expression, and the official fix changes exactly that
expression. Coverage is therefore on the **input axis** — the three ways a
scanner can walk into `sieve[size]`, so a partial fix that special-cases one
shape still fails on the others:

| POV | limit | odd-ified | size | crash shape (vulnerable) | fixed |
|---|---|---|---|---|---|
| `limit_5000_advisory_repro` | 5000 | 4999 (prime) | 2499 | guard passes at `i = size-1` (last prime is the last slot) → read `sieve[2499]` | `++i < size` fails → no read |
| `limit_5001_composite_odd` | 5001 | 5001 (3·1667) | 2500 | trailing-zero walk advances `i` to `size-1`, guard passes a 2nd time → read `sieve[2500]` | same short-circuit → no read |
| `limit_3_minimal` | 3 | 3 (prime) | 1 | `size-1 == 0` passes the guard on a 1-byte sieve → read `sieve[1]` | `++i` = 1, `1 < 1` fails → no read |

`limit_5000_advisory_repro` is byte-for-byte the report's repro (the fix
commit's own ASan trace shows the read at make-prime-list.c:214, 1 byte past a
2499-byte region). `limit_5001_composite_odd` proves the guard is wrong even
when the outermost slot is zero (the trailing-scan route), and
`limit_3_minimal` proves it for the smallest possible allocation. All three
must flip 0 → non-zero under the real fix — none of them can be "repaired" by a
patch that only adjusts the outer loop bound, one input value, or one of the
two shapes.

## Official fix (the "after" oracle)

`official_fix.patch` is the literal upstream commit diff (Pádraig Brady's
version of the fix, pushed in the reporter's name per bug#19784):

```diff
-      while (i < size && sieve[++i] == 0)
+      while (++i < size && sieve[i] == 0)
         ;
```

Increment-then-check instead of check-then-increment: `i == size` now fails the
guard before `sieve[i]` is ever read. It is `git apply`-able against the
dataset source at the buggy commit and was verified with `git apply --check`.

## Build

`src/make-prime-list` is built with AddressSanitizer inside the project
container via the manifest `build_command` (mirroring the dataset Dockerfile's
own build flags: `-fsanitize=address -g -O0 -Wno-error -fcommon`). The dataset
source ships an empty `gnulib` submodule whose `.gitmodules` URL points at the
retired `git://git.sv.gnu.org/gnulib.git`, so the build must obtain gnulib
before running the dataset's standard bootstrap/configure/make line. How gnulib
is obtained depends on whether a usable `.git` is present, which is the crux of
the fix below:

```
if ls gnulib/lib/*.c >/dev/null 2>&1; then
  # gnulib sources already checked out (e.g. an incremental rebuild in the
  # same tree): bootstrap straight off them, no git needed.
  BA="--no-git --gnulib-srcdir=$PWD/gnulib"
elif git rev-parse --git-dir >/dev/null 2>&1; then
  # A real git dir is reachable (this is what `fixpov validate` sees — it
  # copytree's the project-sources checkout, .git and all): rewrite the retired
  # submodule URL in .git/config to the HTTPS mirror and let bootstrap's
  # `git submodule update` fetch the pinned gnulib revision.
  git config submodule.gnulib.url https://git.savannah.gnu.org/git/gnulib.git
  BA=""
else
  # No usable git: an isolated pipeline-run worktree bind-mounts the repo but
  # its .git is a *file* (`gitdir: /path/outside/the/mount`) pointing at a
  # gitdir that does not exist in the container, so any git-repo operation
  # (including `git config`) fails with `fatal: not in a git directory`.
  # gnulib cannot come from the submodule here, so clone the pinned revision
  # directly (a fresh clone makes its own repo, needing nothing from the
  # worktree's broken .git) and bootstrap off it with --no-git.
  rm -rf gnulib && git clone https://git.savannah.gnu.org/git/gnulib.git gnulib \
    && git -C gnulib checkout b9bfe78424b871f5b92e5ee9e7d21ef951a6801d
  BA="--no-git --gnulib-srcdir=$PWD/gnulib"
fi && \
FORCE_UNSAFE_CONFIGURE=1 ./bootstrap --skip-po $BA && \
FORCE_UNSAFE_CONFIGURE=1 ./configure CFLAGS="-fsanitize=address -g -O0 -Wno-error -fcommon" \
  CXXFLAGS="-fsanitize=address -g -O0 -Wno-error -fcommon" \
  LDFLAGS="-fsanitize=address" && \
make -j1 src/make-prime-list
```

`b9bfe78424b871f5b92e5ee9e7d21ef951a6801d` is the exact gnulib commit the
superproject pins for this coreutils revision (`git ls-tree HEAD gnulib`), so
the clone fallback checks out the *same* gnulib the submodule path would — no
version drift between the two branches.

Both git branches write only to `.git/config` (never the tracked
`.gitmodules`) or leave the repo untouched entirely, so `git status` stays
clean and the POV staging never pollutes a persisted diff. `fixpov validate`
re-runs this whole line per checkout (pristine, then patched) and, because it
copies a real `.git`, exercises the `git config` submodule branch; a real
pipeline run's worktree takes the clone fallback. Either way each POV run tests
the binary compiled from the tree under test.

**Why the guard exists.** The original one-line `git config submodule.gnulib.url
… && ./bootstrap …` build worked under `fixpov validate` (real `.git`) but died
in every real pipeline run with `fatal: not in a git directory` (exit 128) — a
run worktree's `.git` is a file pointing outside the Docker bind mount, so
`git config` has no git dir to write to — which recorded every POV as `errored`
and scored the patch `null` instead of measuring real-exploit coverage.

## Rationale notes

- `src/make-prime-list` is a build-time host tool, not a shipped binary — but
  it is the exact subject of gnubug-19784 and the dataset's own alert, so the
  POVs drive it as-is (compiled, then executed, inside the container).
- No POV is weakened: ASan's heap-buffer-overflow (READ of size 1) is detected
  in the program output; a crash-free run means the read never happened.
- Alternative sink interpretations (the sieve-fill loop at line 211 takes the
  same `size` bound but is guarded-by-loop-condition correctly) were checked:
  line 211's `for` loop re-checks `j < size` after `j += p`, so there is no
  second OOB route — line 214 is the only sink.

## Certification

```bash
python -m security_pipeline fixpov validate --project coreutils__coreutils_gnubug-19784_658529a10e05
```