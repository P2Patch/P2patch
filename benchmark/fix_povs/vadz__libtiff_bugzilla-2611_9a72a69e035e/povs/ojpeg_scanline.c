/*
 * Minimal libtiff public-API driver for the OJPEG divide-by-zero POVs.
 *
 *   argv[1] = path to a crafted OJPEG TIFF
 *   argv[2] = number of TIFFReadScanline(row 0) calls (default 1)
 *
 * Reproduces the fault purely through the libtiff public API (TIFFOpen +
 * TIFFReadScanline), independent of any command-line tool. The project is
 * built with -fsanitize=integer-divide-by-zero, so an OJPEG integer
 * divide-by-zero surfaces as a UBSan "runtime error: division by zero"
 * report (or, if UBSan were absent, a hardware SIGFPE).
 *
 * Never asserts anything itself -- the only fault it can surface is one the
 * real libtiff OJPEG codec commits.
 */
#include <stdio.h>
#include <stdlib.h>
#include "tiffio.h"

int main(int argc, char** argv)
{
    int nreads, i;
    TIFF* t;
    tmsize_t sz;
    unsigned char* buf;

    if (argc < 2) {
        fprintf(stderr, "usage: %s file.tif [nreads]\n", argv[0]);
        return 3;
    }
    nreads = (argc >= 3) ? atoi(argv[2]) : 1;
    if (nreads < 1) nreads = 1;

    t = TIFFOpen(argv[1], "r");
    if (t == NULL) {
        fprintf(stderr, "TIFFOpen(%s) failed\n", argv[1]);
        return 3;
    }
    sz = TIFFScanlineSize(t);
    if (sz <= 0) sz = 16;
    buf = (unsigned char*)_TIFFmalloc(sz);
    if (buf == NULL) {
        fprintf(stderr, "alloc failed\n");
        TIFFClose(t);
        return 3;
    }
    for (i = 0; i < nreads; i++) {
        int r = TIFFReadScanline(t, buf, 0, 0);
        fprintf(stderr, "TIFFReadScanline #%d (row 0) -> %d\n", i + 1, r);
    }
    _TIFFfree(buf);
    TIFFClose(t);
    return 0;
}
