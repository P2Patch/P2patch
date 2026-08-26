# libxml2 CVE-2016-1839 — fixPOV notes

**Advisory:** NVD
https://nvd.nist.gov/vuln/detail/CVE-2016-1839 — "Heap-based buffer overread in
the xmlDictAddString function in libxml2 before 2.9.4 ... allows remote
attackers to cause a denial of service (heap-based buffer over-read) via a
crafted XML document." Upstream bug 758605
(https://bugzilla.gnome.org/show_bug.cgi?id=758605), reported by Mateusz
Jurczyk (Project Zero).

**Fix commit:** `a820dbeac29d330bae4be05d9ecd939ad6b4aa33` — "Bug 758605:
Heap-based buffer overread in xmlDictAddString". Adds two bounds checks in
HTMLparser.c:
1. `htmlParseName`: `if (in == ctxt->input->end) return(NULL);` before the
   `*in` dereference that follows the ASCII accelerator scan.
2. `htmlParseNameComplex`: `if (ctxt->input->base > ctxt->input->cur - len)
   return(NULL);` before
   `return(xmlDictLookup(ctxt->dict, ctxt->input->cur - len, len));`.

`official_fix.patch` is the literal upstream HTMLparser.c diff from that commit
(the other hunks touched runtest.c and added test/HTML/758605.html, which are
harness/tests only), verified to `git apply --check` cleanly against the
dataset revision `db07dd613e461df93dde7902c6505629bf0734e9`. This matches the
finder alert (`finder_results_filtered/GNOME_LIBXML2_CVE_2016_1839.json`),
whose trace is HTMLparser.c:2517 -> dict.c:285.

## Root cause / sink

Sink: `HTMLparser.c:htmlParseNameComplex` (return at line 2517). The function
walks a name accumulating `len` and returns
`xmlDictLookup(ctxt->dict, ctxt->input->cur - len, len)`. The trust boundary is
a crafted HTML document whose *name* (entity reference, PI target, or DOCTYPE
name) contains a non-ASCII character: `htmlCurrentChar` (HTMLparser.c:518) sees
the first byte >= 0x80 with the charset still undetected and calls
`xmlSwitchEncoding` -> `xmlSwitchToEncodingInt` -> `xmlSwitchInputEncodingInt`
(parserInternals.c:1205), which allocates a *fresh* input buffer and repositions
`input->cur` to the start of the remaining input. `len` already counts the ASCII
name characters consumed before the switch, so after the switch
`ctxt->input->cur - len` points before the new buffer's base and
`xmlDictLookup` forwards the underflowed pointer unchanged into
`xmlDictAddString` (dict.c:285), whose `memcpy(pool->free, name, namelen)` (and
the preceding `xmlDictComputeFastKey`) reads out of bounds. ASan reports a
`heap-buffer-overflow` READ with the 4096-byte region being the fresh buffer
allocated by `xmlBufCreate` in `xmlSwitchInputEncodingInt`.

## Path coverage

`htmlParseNameComplex` has exactly one caller — `htmlParseName` — and
`htmlParseName` has exactly three callers, all covered by one POV each:

| caller | source construct | POV id |
|---|---|---|
| `htmlParseEntityRef` (HTMLparser.c:2682) | `&name;` entity reference | `entity_ref_name_oob_read` |
| `htmlParsePI` (HTMLparser.c:3153) | `<?target` PI target | `pi_target_name_oob_read` |
| `htmlParseDocTypeDecl` (HTMLparser.c:3424) | `<!DOCTYPE name` doctype name | `doctype_name_oob_read` |

`entity_ref_name_oob_read` uses the literal upstream regression test
`test/HTML/758605.html` (`&:` then latin-1 0xEA then LF; underflow by 1 byte).
`entity_ref_name_oob_read_utf8` re-drives the entity-ref path with a UTF-8
multi-byte character after 16 ASCII chars (underflow by 17 bytes) to cover the
alternate-encoding technique. `pi_target_name_oob_read` and
`doctype_name_oob_read` use the same underflow through the other two callers.
The remaining fix hunk (`htmlParseName`'s `in == end`) was scanned for an
independent trigger: an unterminated all-ASCII name ending exactly at the input
buffer end (`&abc`) does not produce an ASan-detectable overread because
`xmlBuf` keeps a NUL terminator at `content[use]`, so `*in` reads that
terminator in-bounds. That hunk is defense-in-depth (it stops the read of the
buffer terminator outright); it is not independently reproducible as a detected
overread in this build, so it is covered by the same POV architecture rather
than a dedicated POV.

## Official fix (the "after" oracle)

`official_fix.patch` guards both vulnerable dereferences: the `cur - len`
underflow in `htmlParseNameComplex` (the sink the alert names) and the
`in == end` case in `htmlParseName`. Verified empirically on the server:
unpatched `xmllint --html --noout` reports an ASan `heap-buffer-overflow` for
all four fixtures; after applying the patch and rebuilding, the same commands
produce only normal HTML parser errors and zero ASan summaries.

## Certification

```bash
python -m security_pipeline fixpov validate --project GNOME__libxml2_CVE-2016-1839_db07dd613e46
```
