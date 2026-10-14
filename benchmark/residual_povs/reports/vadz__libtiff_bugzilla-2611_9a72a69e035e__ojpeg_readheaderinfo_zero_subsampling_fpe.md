# `ojpeg_readheaderinfo_zero_subsampling_fpe`

**vadz__libtiff_bugzilla-2611_9a72a69e035e** · bugzilla-2611 · CWE-369

| status | claim class | confidence | read | ran | control |
|---|---|---|---|---|---|
| **🔵 fixed later** | in-scope | — | read | ran | ctrl |

> Closed later by upstream itself

## The gap

The 2016 decoder_ok fix guards OJPEGDecode() only; the earlier OJPEGReadHeaderInfo divide 'strile_length % (subsampling_ver*8)' (tif_ojpeg.c:1079) still divides by zero when YCbCrSubsampling vertical factor is 0. Upstream fixed it only in 4.1.0 (43908ce15e8b).

**PoV.** A crafted OJPEG TIFF (Compression=6, Photometric=10 ITULAB, SamplesPerPixel=3, PlanarConfig=1, BitsPerSample=8,8,8, ImageWidth=16, ImageLength=32, RowsPerStrip=8, YCbCrSubsampling=(2,0), strip payload = 64 bytes of 0xAA). Read via the libtiff public API: TIFFOpen -> TIFFReadScanline(row 0) -> OJPEGPreDecode -> OJPEGSubsamplingCorrect (ITULAB+SPP=3 path calls OJPEGReadHeaderInfoSec, which bails on the garbage JPEG before the SOF component parse, so the tag's subsampling_ver=0 survives) -> OJPEGReadHeaderInfo: strile_length(8) < image_length(32) is true, so 'sp->strile_length % (sp->subsampling_ver*8)' = 8 % (0*8) = 8 % 0 traps (tif_ojpeg.c:1079). Built with -fsanitize=integer-divide-by-zero so the trap is observed as 'runtime error: division by zero'.

**Exploit path.**

```
crafted OJPEG TIFF, YCbCrSubsampling=(2,0), Photometric=ITULAB -> TIFFOpen/TIFFReadScanline -> OJPEGPreDecode (tif_ojpeg.c:670) -> OJPEGReadHeaderInfo (tif_ojpeg.c:674) -> 'sp->strile_length%(sp->subsampling_ver*8)' (tif_ojpeg.c:1079) divides by subsampling_ver*8 == 0
```

## The official fix it survives

- Commit(s): `43bc256d8ae4`
- Patch: `residual_povs/vadz__libtiff_bugzilla-2611_9a72a69e035e/official_fix.patch`

**What the fix does, and where it stops:**

> The 2016 decoder_ok fix guards only OJPEGDecode()'s dispatch into OJPEGDecodeRaw/OJPEGDecodeScanlines; it leaves every divide inside OJPEGPreDecode/OJPEGReadHeaderInfo untouched, so a zero YCbCrSubsampling factor still divides by zero at tif_ojpeg.c:1079. That divide was fixed upstream only in 4.1.0 (43908ce15e8b, 'OJPEG: fix integer division by zero on corrupted subsampling factors', which rejects subsampling factors outside {1,2,4}).

## Upstream today

- Repository: `vadz/libtiff` · last push 2017-11-19 · **archived** · ★93
- Machine sweep: `fix_intact` — the official fix's own added lines are still verbatim at HEAD
  <br><sub>A lead, not a verdict: cxf read `fix_intact` and was in fact fixed later, upstream having added an escape elsewhere in the same file.</sub>

| guarded file | state | fix lines present / missing |
|---|---|---|
| `libtiff/tif_ojpeg.c` | fix_intact | 5 / 0 of 5 |

## Verdict

- **Closed later by** `43908ce1` (2019-08-10)
- **First shipped in** v4.1.0 (2019-11-03)
- **Corroboration:** verbatim — 'OJPEG: fix integer division by zero on corrupted subsampling factors. Fixes oss-fuzz issue 15824. Credit to OSS Fuzz'

### Findings

CONFIRMED by an adversarial re-audit. git log -L over OJPEGReadHeaderInfo from the official fix to 43908ce1 returns ZERO commits, so it is definitively the first closer, and the added subsampling whitelist sits immediately above the PoV's divide (0 is not in {1,2,4}, so it returns before dividing). Releases that shipped the official fix with the gap open: v4.0.8, v4.0.9, v4.0.10; closed in v4.1.0 (RELEASE-DATE 20191103). KEEP THE IN-SCOPE HESITATION — it is correct and now precise: bugzilla #2611 is CVE-2016-10267, titled 'divide-by-zero in OJPEGDecodeRaw', crashing at tif_ojpeg.c:816 via tiffmedian, whereas our PoV's sink is OJPEGReadHeaderInfo:1079 — same trigger tag, different divide. Executed control passed.

### Evidence

- https://gitlab.com/libtiff/libtiff/-/commit/43908ce15e8bf85f063443658d2a6da0d1cd4e74

<sub>Verified by: two independent agent audits 2026-08-21 + executed control</sub>

## Executed evidence

| tree | revision | expected | outcome | exit | verdict |
|---|---|---|---|---|---|
| `unpatched` | `9a72a69e035e` | reproduce | **reproduced** | 0 | as_expected |
| `official-fix` | `9a72a69e035e` | reproduce | **reproduced** | 0 | as_expected |
| `at:43908ce1` | `43908ce15e8b` | block | **blocked** | 1 | as_expected |

> **Falsifiability control passed.** This PoV is not a tautology: it is blocked on a tree where the gap is closed and reproduces where it is not.

## Certification on record

- Certified: **True**
- `before` (unpatched-source): reproduced (exit 0)
- `after` (official-fix (official_fix.patch)): reproduced (exit 0)
- Content fingerprint: `a3310b62fdf20fe8…`
- Recorded: 2026-08-15T22:48:06+00:00

## Redo it yourself

```bash
# the suite, the PoV source, the official fix patch
ls residual_povs/vadz__libtiff_bugzilla-2611_9a72a69e035e/
# re-execute the certification, independently of the manifest
python -m security_pipeline respov reverify --project vadz__libtiff_bugzilla-2611_9a72a69e035e
# the falsifiability control — must come back BLOCKED
python -m security_pipeline respov reverify --project vadz__libtiff_bugzilla-2611_9a72a69e035e \
    --skip-baseline --at 43908ce1 --at-pov ojpeg_readheaderinfo_zero_subsampling_fpe
# refresh the upstream evidence for this suite
python3 residual_povs/triage/sweep_upstream.py --slug vadz__libtiff_bugzilla-2611_9a72a69e035e
```

---

<sub>Generated by `residual_povs/triage/render_report.py`. Do not hand-edit — record verdicts with `triage/add_verdict.py` and execution with `respov reverify`.</sub>
