# vadz/libtiff bugzilla-2633 — fixPOV notes

**Advisory:** bugzilla.maptools.org 2633
(http://bugzilla.maptools.org/show_bug.cgi?id=2633), reported by Agostino
Sarubbo (reproducer `00107-libtiff-heapoverflow-PSDataColorContig`). No CVE
entry maps cleanly to this report in the dataset (`project_info.csv` uses
`bugzilla-2633` as the identifier). The same commit also fixes bugzilla 2634
(`PSDataBW()`, reproducer `00108`) — a **distinct** over-read in a different
function, out of scope for this project.

**Fix commit:** `5ed9fea523316c2f5cec4d393e4d5d671c2dbc33` — "fix 2
heap-based buffer overflows (in PSDataBW and PSDataColorContig)". For this
project `official_fix.patch` carries **only** the `PSDataColorContig()` hunk
(the `es <= 0` guard) — the hunk that fixes bugzilla-2633 — applied to the
dataset revision of `tools/tiff2ps.c` (pre-image blob `ae296e9` == the
upstream diff's pre-image), verified to `git apply` cleanly. The `PSDataBW()`
hunk is deliberately excluded: it fixes bugzilla-2634, a different bug whose
over-read is in `PSDataBW()`'s alpha loop (`while (cc-- > 0)` → `> 1`), and
including it in this project's oracle would conflate the two issues.

**Root cause:** `PSDataColorContig()` (tools/tiff2ps.c:2434) computes the
extra-samples stride with no validation:
`int breaklen = MAXLINE, es = samplesperpixel - nc;` (line 2437). The
alpha-matte adjustment `adjust = 255 - cp[nc];` (line 2470) reads `nc` bytes
**ahead** of the current pixel; whenever `es <= 0` the row pointer never stays
ahead of where `cp[nc]` overruns the `tf_bytesperrow`-sized heap buffer
`tf_buf` — an ASan heap-buffer-overflow **READ** of size 1 at tiff2ps.c:2470
(CWE-125). The fix rejects the call up front:
`if (es <= 0) { TIFFError(filename, "Inconsistent value of es: %d", es); return; }`.

**How the fixture drives `es <= 0` (verified empirically):** the PoC is byte-
identical to asarubbo's `00107-libtiff-heapoverflow-PSDataColorContig`. Its IFD
is deliberately malformed — `StripByteCounts=4` but the declared geometry
(4px × 1 row × 4 samples × 8 bits) needs 16 bytes, tags are out of order, and
`YResolution`/`Software` point at non-existent data (libtiff logs
"Invalid TIFF directory; tags are not sorted" and "IO error during reading of
YResolution"). Instead of rejecting, this libtiff revision coerces the row
geometry from the strip byte count, so `PSDataColorContig` runs with a **4-byte**
`tf_buf` and `es = samplesperpixel - nc = -2` (the `nc=3` RGB branch of
`PSpage`, tiff2ps.c:2347). The guard in the fixed build trips with the
observed message `Inconsistent value of es: -2.` — matching the pre-fix crash
at the same call. Certified evidence:

- **before (unpatched, f3069a5adc65):** `ERROR: AddressSanitizer:
  heap-buffer-overflow` — `READ of size 1` at address 0x…1b4, described as
  "located 0 bytes to the right of 4-byte region [0x…1b0,0x…1b4)", allocated by
  `_TIFFmalloc` (tiff2ps.c:2443); stack: `PSDataColorContig` tiff2ps.c:2470 ←
  `PSpage` tiff2ps.c:2347 ← `TIFF2PS` tiff2ps.c:1606 ← `main` tiff2ps.c:473.
- **after (official fix):** no sanitizer report; tiff2ps prints
  `Inconsistent value of es: -2.` and emits a well-formed EPS; exit 1.

**Coverage argument:** the alert's single CodeQL trace names exactly this
pair of sites — `tools/tiff2ps.c:2437` (`es = samplesperpixel - nc` without
validation) → `tools/tiff2ps.c:2470` (`adjust = 255 - cp[nc]`). The fix's one
`es <= 0` guard closes every reachable shape of the bug at once: with
well-formed headers `es < 0` requires `samplesperpixel < nc` (only reachable
through the same malformed-geometry coercion this PoC exploits, or the
SEPARATED branch with `spp < 4`), and `es == 0` (builds with bogus tag
fix-ups) hits the identical guard + read-one-past-buffer pattern. There is no
second call-site shape that reaches line 2470 with `es > 0` yet still
overruns — with `es >= 1` the row walk's `cp` always advances past the
matte-read window, so the official fix covers the entire path with the branch
this POV triggers. `PSDataBW()` (bugzilla-2634) and `PSDataColorSeparate()`
are separate functions and separate bugs; the latter is not touched by this
fix commit at all.

**PoC provenance:** `colorcontig_oob.tif` is the original
GraphicsMagick-generated file from
https://github.com/asarubbo/poc (`00107-libtiff-heapoverflow-PSDataColorContig`),
byte-copied into `povs/`.