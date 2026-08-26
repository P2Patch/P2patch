# vadz/libtiff bugzilla-2611 — residual-gap POV notes

**What "residual" means here.** The official CVE-2016-10267 fix
(`43bc256d8ae44b92d2734a3c5bc73957a4d7c1ec`, the `decoder_ok` guard) adds a
flag that makes **`OJPEGDecode()` early-exit** when the preceding
`OJPEGPreDecode()` did not reach its successful end. That closes exactly one
sink: the `OJPEGDecodeRaw`/`OJPEGDecodeScanlines` `cc % bytes_per_line` divide
(tif_ojpeg.c:816/864), which is the fixPOV set. The guard sits at the
**decode** boundary, so every integer divide that happens *earlier* — inside
`OJPEGPreDecode` itself, in `OJPEGReadHeaderInfo` and `OJPEGWriteHeaderInfo` —
is entirely unreached by the 2016 fix. Those are OJPEG divide-by-zeros upstream
closed only years later. They reproduce on the unpatched tree **and still after
`official_fix.patch`** → residual POVs.

`residual_of` = `43bc256d8ae4` (the fix these POVs are proven to survive).

---

## R1 (CERTIFIED) — `ojpeg_readheaderinfo_zero_subsampling_fpe`

**Sink:** `OJPEGReadHeaderInfo`, tif_ojpeg.c:1079

```c
	if (sp->strile_length<sp->image_length)          /* line 1077 */
	{
		if (sp->strile_length%(sp->subsampling_ver*8)!=0)   /* line 1079: divisor == 0 */
```

**Divisor is zero when** `sp->subsampling_ver == 0`. That value comes straight
from the file's `YCbCrSubsampling` tag (`OJPEGVSetField` assigns
`subsampling_ver` from the tag's second short), and nothing between the tag read
and line 1079 clamps it to a legal value on this input:

- The fixture uses **`Photometric = 10` (ITULAB)**, not YCbCr. `OJPEGSubsamplingCorrect`
  (tif_ojpeg.c:990) only forces `subsampling_hor/ver = 1` when
  `samplesperpixel != 3` **or** photometric is neither YCbCr nor ITULAB. With
  ITULAB + SamplesPerPixel=3 it takes the *else* branch (line 999) and calls
  `OJPEGReadHeaderInfoSec` to read subsampling from the embedded JPEG's SOF.
- The strip payload is **64 bytes of `0xAA`** — no valid SOI/SOF — so
  `OJPEGReadHeaderInfoSec` bails before the component parse could overwrite the
  subsampling. The tag's `subsampling_ver = 0` therefore **survives**.
- ITULAB (rather than YCbCr) is also what lets the directory pass
  `TIFFReadDirectory` / `tif_strip.c`: the YCbCr-specific subsampling
  validation and strip-size math (`TIFFVStripSize` with subsampling) are only
  applied for `PHOTOMETRIC_YCBCR`.
- `ImageLength = 32`, `RowsPerStrip = 8` ⇒ `strile_length (8) < image_length (32)`
  is true, so line 1077's branch is **entered** and line 1079 divides.

**Driver:** the libtiff public API (`povs/ojpeg_scanline.c`, shared with the GT
`libapi` POV): `TIFFOpen` → one `TIFFReadScanline(t,buf,0,0)`. The first read
runs `OJPEGPreDecode` → `OJPEGReadHeaderInfo` → the line-1079 divide. Only one
read is needed (unlike the GT decode-sink POV, this fault is in pre-decode).

**Oracle:** built with `-fsanitize=integer-divide-by-zero` (same build as the
GT set), so `8 % 0` surfaces as `runtime error: division by zero`;
`run.sh` sets `UBSAN_OPTIONS=halt_on_error=1` and also accepts a raw SIGFPE
(rc 136). A compile/link failure of the driver maps to exit 2 (harness error),
never 1 (blocked).

**Upstream close:** libtiff **4.1.0**, commit
`43908ce15e8bf85f063443658d2a6da0d1cd4e74` ("OJPEG: fix integer division by zero
on corrupted subsampling factors"), which rejects any subsampling factor outside
`{1,2,4}` before the modulo. That commit is **years after** the 2016 `decoder_ok`
fix, so this divide reproduces before *and* after `official_fix.patch` — the
residual property. (A pipeline patch that additionally clamps/validates the
subsampling factor, or that guards `OJPEGReadHeaderInfo`, would flip this POV to
`blocked` and earn beyond-upstream credit.)

Fixture generator: `povs/make_r1_fixture.py` (documents every tag);
`povs/poc_r1_ojpeg_readheader_subsampling.tif` is the committed 248-byte output.

---

## R2 (SKIPPED — not reliably constructible) — `ojpeg_writeheaderinfo_zero_subsampling_fpe`

**Intended sink:** `OJPEGWriteHeaderInfo`, tif_ojpeg.c:1187

```c
	sp->subsampling_convert_ylinelen=((sp->strile_width+sp->subsampling_hor*8-1)/(sp->subsampling_hor*8) ...);
```

a divide by `sp->subsampling_hor*8` (and line 1189 `.../sp->subsampling_hor`),
zero when `subsampling_hor == 0`. This is the libtiff **issue #554** divide,
closed upstream only in **4.5.1**, commit
`d0c721cad7e5e90904b0112ba56be28c35fe4394` ("tif_ojpeg.c fix 554 by checking for
division by zero") — likewise untouched by the 2016 `decoder_ok` fix, so it is a
genuine residual gap in principle.

**Why it is not shipped as a certified POV.** Unlike R1's sink, line 1187 is
reached **only after** `OJPEGWriteHeaderInfo` calls libjpeg's
`jpeg_read_header` (tif_ojpeg.c:1174) and it *succeeds* — which requires a
**valid, libjpeg-parseable embedded JPEG stream** (SOI + a well-formed SOF +
quant/Huffman tables + SOS), not the `0xAA` garbage R1 relies on. Worse, to keep
`subsampling_hor == 0` all the way to line 1187, libtiff's *own* SOF parse
(`OJPEGReadHeaderInfoSecStreamSof`, run from `OJPEGSubsamplingCorrect` for the
ITULAB/SPP=3 path) must **not** overwrite the zeroed tag value — but a valid SOF
carries per-component sampling factors ≥ 1, from which libtiff derives a
non-zero subsampling. Reaching `subsampling_hor == 0` at the divide therefore
depends on a specific pathological SOF (the shape the public #554 "pocmin"
uses), which cannot be produced by any normal JPEG encoder (libjpeg will not
emit a component sampling factor of 0) and which I could not hand-craft into a
byte sequence that both (a) survives `TIFFReadDirectory`, (b) is accepted by
libtiff's `OJPEGReadHeaderInfoSec`, (c) is accepted by libjpeg's
`jpeg_read_header`, and (d) still yields `subsampling_hor == 0` at line 1187 —
reliably and deterministically. The public reproducer for #554 is a binary blob
in the upstream issue tracker; it is not reproduced here because I could not
retrieve it as verifiable bytes and certify it end-to-end under this build.

Per the authoring contract, a candidate that cannot be certified end-to-end is
**documented and dropped, never forced**. R1 already demonstrates the residual
class (an OJPEG pre-decode divide the 2016 fix does not reach); R2 would be a
second instance of the same class, so no coverage of a distinct residual
*mechanism* is lost — only a second sink site of the "zero subsampling factor"
family. If the #554 pocmin bytes are obtained later, this POV can be added with
the same `povs/ojpeg_scanline.c` driver (one `TIFFReadScanline`, single strip so
R1's line-1079 divide is skipped by `strile_length >= image_length`).

---

## Certification

```
python3 -m security_pipeline respov validate --project vadz__libtiff_bugzilla-2611_9a72a69e035e
```

certifies R1 by proving `poc_r1_...tif` reproduces (exit 0, UBSan divide-by-zero
at tif_ojpeg.c:1079) on **both** the pristine source and the source with
`official_fix.patch` applied — the inverted residual oracle.
