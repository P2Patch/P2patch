# vadz/libtiff bugzilla-2611 — fixPOV notes

**Advisory:** MapTools bugzilla 2611
http://bugzilla.maptools.org/show_bug.cgi?id=2611 — "libtiff: divide-by-zero in
OJPEGDecodeRaw (tif_ojpeg.c)", reported 2016-11-28 by Agostino Sarubbo, RESOLVED
FIXED (assigned to Frank Warmerdam, CVE-2016-10267, CWE-369). The original
stacktrace attachment shows `AddressSanitizer: FPE ... tif_ojpeg.c:816:8 in
OJPEGDecodeRaw` driven by `tiffmedian $FILE /tmp/foo` (the report typos the
tool as "tiffmedia"; the tested binary is `tools/tiffmedian`).

**Fix commit:** `43bc256d8ae44b92d2734a3c5bc73957a4d7c1ec` (Even Rouault,
2016-12-03), exactly one commit after the dataset revision `9a72a69e035e`
(2016-12-02, the direct parent — "libtiff/tif_dirread.c: modify
ChopUpSingleUncompressedStrip() ..." fixes #2608). The commit message:
"make OJPEGDecode() early exit in case of failure in OJPEGPreDecode(). This
will avoid a divide by zero, and potential other issues." The
`libtiff/tif_ojpeg.c` hunks apply verbatim to the dataset checkout (the local
file is byte-identical to 4.0.7's; the abbreviated blob hashes 1ccc3f9/f19e8fd
in the generated `official_fix.patch` match upstream's exactly); the ChangeLog
hunk is dropped (security-relevant hunks only). `git apply --check` passes.
The dataset commit `43bc256d8ae4` is also the base of two other dataset
projects (`cve-2016-10092`, `cve-2016-10272`) — they **already contain this
fix**, which is why the OJPEG fix is present in several sibling images.

**Root cause:** `OJPEGPreDecode()` (libtiff/tif_ojpeg.c:666-726) reads and
validates the embedded old-style-JPEG stream in stages that can fail
(`OJPEGReadHeaderInfo`, `OJPEGReadSecondarySos`, `OJPEGWriteHeaderInfo`, the
skip loop) and returns 0 on any of them. But nothing prevents
`OJPEGDecode()` (tif_ojpeg.c:785-800) from still being invoked afterwards on a
**re-read of the same row**. The mechanism is a **stale `tif_curstrip`**:
`TIFFReadScanline` seeks via `TIFFSeek`, which only refills (and runs
`tif_predecode = OJPEGPreDecode`) when the target strip differs from
`tif->tif_curstrip`. On the *first* read of row 0, `TIFFStartStrip` sets
`tif_curstrip = 0` **before** predecode runs, then predecode fails inside
`OJPEGReadHeaderInfo` and `TIFFReadScanline` returns -1. On a *second* read of
that same row 0, `strip == tif_curstrip`, so `TIFFSeek` skips the refill —
**no predecode runs** — and `TIFFReadScanline` proceeds straight to
`tif_decoderow = OJPEGDecode` with the codec state still zero-initialized
(`bytes_per_line == 0`). tiffmedian triggers exactly this: it reads row 0
twice (its palette-histogram pass re-reads the first scanline). Verified by
backtrace: the fixed build prints the guard's "Cannot decode" message on that
second read, proving decode runs after a pre-decode failure.
OJPEGDecode then dispatches straight into `OJPEGDecodeRaw()` (query_style==0,
the default before any successful write-header) with no check that pre-decode
ever completed:

```c
	if (cc%sp->bytes_per_line!=0)     /* tif_ojpeg.c:816 */
```

`sp->bytes_per_line` is only ever assigned inside the *successful* branch of
`OJPEGWriteHeaderInfo` (tif_ojpeg.c:1222/1232), so a pre-decode that failed
earlier leaves it at its zero-initialized value, and `cc % 0` is an integer
divide-by-zero — delivered as SIGFPE (what the original ASan-FPE stacktrace
shows) or a UBSan `-fsanitize=integer-divide-by-zero` report. In the PoC
`cc = tif_scanlinesize = 3` (a 1x1 RGB image), so every single decode call
hits the modulo.

The official fix adds a `decoder_ok` flag to `OJPEGState` (zero-initialized),
sets it to 1 only at the successful end of `OJPEGPreDecode`, and makes
`OJPEGDecode` early-exit (`TIFFErrorExt ... "Cannot decode: decoder not
correctly initialized"; return 0`) while it is unset — so neither
`OJPEGDecodeRaw` nor `OJPEGDecodeScanlines` can run on uninitialized state.

**The POV** (`ojpeg_decoderaw_divide_by_zero`): runs the **real
`tools/tiffmedian` CLI** (the binary from the original report) against the
**canonical upstream reproducer**: asarubbo/poc
`00083-libtiff-fpe-OJPEGDecodeRaw`, a 416-byte file whose header declares
BigTIFF (version 0x2b/43, so offsets are 8-byte) and an OJPEG (Compression=6,
Photometric=3 (palette / RGB Palette, not RGB=2), SamplesPerPixel=3, 1x1)
directory whose embedded JPEG stream is garbage — i.e. `OJPEGPreDecode` fails
at `OJPEGReadHeaderInfo`. The fixture is shipped byte-identical
(md5 `d985412718a1df25d7f062f9a67b7ae1`).

**Second POV** (`ojpeg_decoderaw_divzero_libapi`): the same sink and the same
fixture, driven through the **libtiff public API** instead of the tiffmedian
tool. A ~20-line C driver (`povs/ojpeg_scanline.c`) compiled against the static
`libtiff/.libs/libtiff.a` does `TIFFOpen` → `TIFFReadScanline(t,buf,0,0)` (fails
in `OJPEGReadHeaderInfo`) → **`TIFFReadScanline(t,buf,0,0)` again**. The second
read of row 0 finds `strip == tif_curstrip` (set by the first read's
`TIFFStartStrip` before predecode), so `TIFFSeek` skips the refill/predecode and
`OJPEGDecode` runs on the zero-initialized state → `3 % 0` at
`OJPEGDecodeRaw` (tif_ojpeg.c:816). This decouples the fixPOV coverage
from the specific behaviour of any one CLI tool; the official `decoder_ok` fix
blocks it identically (OJPEGDecode early-exits on the second read).

**Sanitizer:** the project is built with `-fsanitize=integer-divide-by-zero`
(as the dataset Dockerfile/build_info row already does), so the trap is
observable as the UBSan "runtime error: division by zero" report; `run.sh`
exports `UBSAN_OPTIONS=halt_on_error=1` so the process aborts at the trap and
the outcome is deterministic. `run.sh` also treats a raw SIGFPE exit
(rc=136 = 128+8) as reproduced, covering the hardware-idiv mode that the
original report's ASan-FPE stacktrace observed; the fixed build never divides
(unverified-crash-free: it prints the error and tiffmedian exits 0).
Verified empirically against sibling-built images at both revisions: the
pre-fix tree (cve-2016-5321 image, `0ba5d8814a17`) crashes with
`AddressSanitizer: FPE ... OJPEGDecodeRaw tif_ojpeg.c:816` — byte-for-byte the
bugzilla stacktrace — and the post-fix tree (cve-2017-7595 image,
`2c00d31b6cd5`) prints "OJPEGDecode: Cannot decode: decoder not correctly
initialized" and exits cleanly, no division.

**Coverage argument — every sink the fix guards:**

The alert (`finder_results_filtered/VADZ_LIBTIFF_BUGZILLA_2611.json`)
enumerates exactly one source-to-sink trace: the unguarded `OJPEGDecode()`
dispatch (trace line 785) into `OJPEGDecodeRaw()`'s `cc % sp->bytes_per_line`
(816). The fix guards that single dispatcher, and there is exactly one
reachable dividing sink for this bug:

| POV id                          | driver                     | sink                                          | trigger stage of pre-decode failure |
|---------------------------------|----------------------------|-----------------------------------------------|-------------------------------------|
| `ojpeg_decoderaw_divide_by_zero`| tiffmedian CLI             | OJPEGDecodeRaw `cc%bytes_per_line` (line 816)  | OJPEGReadHeaderInfo (tif_ojpeg.c:674) |
| `ojpeg_decoderaw_divzero_libapi`| libtiff public API (2 reads)| OJPEGDecodeRaw `cc%bytes_per_line` (line 816)  | OJPEGReadHeaderInfo (tif_ojpeg.c:674) |

The sibling sink `OJPEGDecodeScanlines()` (tif_ojpeg.c:864, the
query_style==1 branch) is **not reachable** via this bug: `libjpeg_jpeg_query_style`
is only ever assigned inside `OJPEGWriteHeaderInfo` (lines 1182/1231), the same
function that assigns `bytes_per_line` — so a run that would take that branch
has already set `bytes_per_line` to a non-zero value (≥1) and the modulo cannot
trap. Both branches of the fix's guard sit *above* the query_style dispatch, so
one POV exercises the guard completely.

**Uncovered paths / residual analysis:**
- A predecode-stage failure in `OJPEGReadSecondarySos`/`OJPEGWriteHeaderInfo`/
  the skip loop produces the identical state (bytes_per_line==0) and the same
  sink, but could not be turned into a separate *certifiable* fixture from the
  corpus: the canonical reproducer already fails at the earliest stage
  (`OJPEGReadHeaderInfo`), and hand-mutating the BigTIFF directory to reach a
  later stage was not achievable without weakening determinism (the file's
  value offsets point into the mutated header). The fix's guard is
  stage-agnostic, so no coverage is lost.
- Divisions the 2016 `decoder_ok` fix does NOT reach (they sit *before* the
  OJPEGDecode dispatch it guards) are captured as **residual POVs** in
  `residual_povs/vadz__libtiff_bugzilla-2611_9a72a69e035e/`, not here:
  `OJPEGReadHeaderInfo`'s own `strile_length % (subsampling_ver*8)`
  (tif_ojpeg.c:1079, reached with `YCbCrSubsampling` vertical factor 0 under
  Photometric=ITULAB — closed upstream only in 4.1.0, commit 43908ce15e8b), and
  the later issue-#554 divide in `OJPEGWriteHeaderInfo`'s subsampling arithmetic
  (tif_ojpeg.c:1187, closed upstream only in 4.5.1, commit d0c721cad7e5). These
  reproduce *against* the official fix by definition, so they cannot be
  fixPOVs — see the residual set's NOTES.md.

**Verification protocol:** `python -m security_pipeline fixpov validate
--project vadz__libtiff_bugzilla-2611_9a72a69e035e` builds the project image,
runs the POV against the pristine checkout (expect UBSan division-by-zero
report -> exit 0) and against the checkout with `official_fix.patch` applied
(expect "Cannot decode" early-exit -> exit != 0).