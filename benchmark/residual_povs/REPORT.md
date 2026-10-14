# Residual-gap audit — overview

*Generated 2026-08-21T13:09:21Z. One row per certified residual PoV. Click a PoV for its full dossier.*

A **residual PoV** is an exploit that still reproduces after a project's official CVE fix. Certification proves it is a usable instrument; it does not prove the gap mattered. This audit closes that distance, and each row is graded on three independent marks:

| mark | meaning |
|---|---|
| `read` | a person read upstream's current code and history for this PoV |
| `ran` | we re-executed the PoV — reproduces unpatched **and** after the official fix — recorded outside the manifest |
| `ctrl` | proven falsifiable: `blocked` on a tree where the gap is known closed |

## Where it stands

- **36 certified residual PoVs** across **22 CVE suites**
- **36/36 re-executed** independently; **13 falsifiability controls passed**

| status | PoVs | meaning |
|---|---|---|
| 🔵 fixed later | 30 | Closed later by upstream itself |
| ⚪ superseded | 6 | Never shipped open — an artifact of the chosen baseline |

**Only `fixed-later` and `open-at-head` support an upstream-miss claim.** `superseded-in-release` means no released tree ever had the gap — it is an artifact of which commit the benchmark treats as the official fix. `unsound` means no patch can block the PoV without deleting the feature, so it scores every patch for a reason unrelated to the patch, and must be excluded from the residual score.

## Every PoV

| project | PoV | CVE | status | class | reach | lag | read | ran | ctrl | detail |
|---|---|---|---|---|---|---|:--:|:--:|:--:|---|
| `asf__cxf` | `stylesheet_pathinfo` | CVE-2016-6812 | 🔵 fixed later | in-scope | — | 3.9y | read | ran | – | [dossier](reports/asf__cxf_CVE-2016-6812_3.0.11__stylesheet_pathinfo.md) |
| `asf__cxf` | `stylesheet_pathinfo` | CVE-2019-17573 | 🔵 fixed later | in-scope | — | 9mo | read | ran | – | [dossier](reports/asf__cxf_CVE-2019-17573_3.2.11__stylesheet_pathinfo.md) |
| `codehaus-plexus__plexus-archiver` | `shared_prefix_tar` | CVE-2018-1002200 | 🔵 fixed later | in-scope | — | 4.9y | read | ran | – | [dossier](reports/codehaus-plexus__plexus-archiver_CVE-2018-1002200_3.5__shared_prefix_tar.md) |
| `codehaus-plexus__plexus-archiver` | `shared_prefix_zip` | CVE-2018-1002200 | 🔵 fixed later | in-scope | — | 4.9y | read | ran | – | [dossier](reports/codehaus-plexus__plexus-archiver_CVE-2018-1002200_3.5__shared_prefix_zip.md) |
| `codehaus-plexus__plexus-utils` | `residual_1_shared_prefix_sibling` | CVE-2022-4244 | 🔵 fixed later | in-scope | — | 9.5y | read | ran | ctrl | [dossier](reports/codehaus-plexus__plexus-utils_CVE-2022-4244_3.0.23__residual_1_shared_prefix_sibling.md) |
| `dromara__hutool` | `residual_fileapi_sibling_prefix` | CVE-2018-17297 | 🔵 fixed later | in-scope | — | 4.8y | read | ran | ctrl | [dossier](reports/dromara__hutool_CVE-2018-17297_4.1.11__residual_fileapi_sibling_prefix.md) |
| `dromara__hutool` | `residual_unzip_sibling_prefix` | CVE-2018-17297 | 🔵 fixed later | in-scope | — | 4.8y | read | ran | ctrl | [dossier](reports/dromara__hutool_CVE-2018-17297_4.1.11__residual_unzip_sibling_prefix.md) |
| `gdraheim__zziplib` | `zip64_truncated_extra_block_oob_read` | CVE-2017-5976 | 🔵 fixed later | in-scope | — | — | read | ran | – | [dossier](reports/gdraheim__zziplib_CVE-2017-5976_3a4ffcdd7870__zip64_truncated_extra_block_oob_read.md) |
| `gnome__libxml2` | `snprintf_element_content_null_deref` | CVE-2017-5969 | 🔵 fixed later | in-scope | — | — | read | ran | ctrl | [dossier](reports/gnome__libxml2_CVE-2017-5969_362b3229__snprintf_element_content_null_deref.md) |
| `libming__libming` | `bitrate_table_oob_read` | CVE-2016-9264 | 🔵 fixed later | adjacent | — | — | read | ran | ctrl | [dossier](reports/libming__libming_CVE-2016-9264_cc6a386__bitrate_table_oob_read.md) |
| `nahsra__antisamy` | `residual_livelist_html_xmp_anchor_javascript` | CVE-2022-28367 | 🔵 fixed later | in-scope | — | 13d | read | ran | ctrl | [dossier](reports/nahsra__antisamy_CVE-2022-28367_1.6.5__residual_livelist_html_xmp_anchor_javascript.md) |
| `nahsra__antisamy` | `residual_livelist_xhtml_xmp_script` | CVE-2022-28367 | 🔵 fixed later | in-scope | — | 13d | read | ran | ctrl | [dossier](reports/nahsra__antisamy_CVE-2022-28367_1.6.5__residual_livelist_xhtml_xmp_script.md) |
| `skyrpex__potrace` | `res_bmp_coltable_ncolors_oob` | CVE-2013-7437 | 🔵 fixed later | in-scope | — | — | read | ran | – | [dossier](reports/skyrpex__potrace_CVE-2013-7437_189777a2bd50__res_bmp_coltable_ncolors_oob.md) |
| `solon` | `symlink_follow_escape` | CVE-2025-1584 | 🔵 fixed later | in-scope | — | 1.5y | read | ran | ctrl | [dossier](reports/solon_CVE-2025-1584_v3.0.8__symlink_follow_escape.md) |
| `solon` | `trailing_parent_dir_escape` | CVE-2025-1584 | 🔵 fixed later | in-scope | — | 1.5y | read | ran | ctrl | [dossier](reports/solon_CVE-2025-1584_v3.0.8__trailing_parent_dir_escape.md) |
| `srikanth-lingala__zip4j` | `residual_1_shared_prefix_file` | CVE-2018-1002202 | 🔵 fixed later | in-scope | — | 8mo | read | ran | – | [dossier](reports/srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2__residual_1_shared_prefix_file.md) |
| `srikanth-lingala__zip4j` | `residual_2_shared_prefix_directory` | CVE-2018-1002202 | 🔵 fixed later | in-scope | — | 8mo | read | ran | – | [dossier](reports/srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2__residual_2_shared_prefix_directory.md) |
| `vadz__libtiff` | `contigtiles2separatestrips_oob` | CVE-2017-5225 | 🔵 fixed later | in-scope | — | — | read | ran | ctrl | [dossier](reports/vadz__libtiff_CVE-2017-5225_393881da1a7f__contigtiles2separatestrips_oob.md) |
| `vadz__libtiff` | `refblackwhite_default_bps64_shift` | CVE-2017-7601 | 🔵 fixed later | adjacent | — | — | read | ran | – | [dossier](reports/vadz__libtiff_CVE-2017-7601_3144e57770c1__refblackwhite_default_bps64_shift.md) |
| `vadz__libtiff` | `ojpeg_readheaderinfo_zero_subsampling_fpe` | bugzilla-2611 | 🔵 fixed later | in-scope | — | — | read | ran | ctrl | [dossier](reports/vadz__libtiff_bugzilla-2611_9a72a69e035e__ojpeg_readheaderinfo_zero_subsampling_fpe.md) |
| `yamcs__yamcs` | `bucket_name_traversal_read` | CVE-2023-45277 | 🔵 fixed later | in-scope | — | 12mo | read | ran | – | [dossier](reports/yamcs__yamcs_CVE-2023-45277_5.8.6__bucket_name_traversal_read.md) |
| `yamcs__yamcs` | `delete_sibling_prefix` | CVE-2023-45277 | 🔵 fixed later | in-scope | — | 10mo | read | ran | – | [dossier](reports/yamcs__yamcs_CVE-2023-45277_5.8.6__delete_sibling_prefix.md) |
| `yamcs__yamcs` | `find_sibling_prefix` | CVE-2023-45277 | 🔵 fixed later | in-scope | — | 10mo | read | ran | – | [dossier](reports/yamcs__yamcs_CVE-2023-45277_5.8.6__find_sibling_prefix.md) |
| `yamcs__yamcs` | `get_sibling_prefix` | CVE-2023-45277 | 🔵 fixed later | in-scope | — | 10mo | read | ran | – | [dossier](reports/yamcs__yamcs_CVE-2023-45277_5.8.6__get_sibling_prefix.md) |
| `yamcs__yamcs` | `put_sibling_prefix` | CVE-2023-45277 | 🔵 fixed later | in-scope | — | 10mo | read | ran | – | [dossier](reports/yamcs__yamcs_CVE-2023-45277_5.8.6__put_sibling_prefix.md) |
| `yamcs__yamcs` | `bucket_name_traversal` | CVE-2023-45278 | 🔵 fixed later | in-scope | — | 12mo | read | ran | – | [dossier](reports/yamcs__yamcs_CVE-2023-45278_5.8.6__bucket_name_traversal.md) |
| `yamcs__yamcs` | `delete_sibling_prefix_escape` | CVE-2023-45278 | 🔵 fixed later | in-scope | — | 10mo | read | ran | – | [dossier](reports/yamcs__yamcs_CVE-2023-45278_5.8.6__delete_sibling_prefix_escape.md) |
| `yamcs__yamcs` | `find_sibling_prefix_escape` | CVE-2023-45278 | 🔵 fixed later | in-scope | — | 10mo | read | ran | – | [dossier](reports/yamcs__yamcs_CVE-2023-45278_5.8.6__find_sibling_prefix_escape.md) |
| `yamcs__yamcs` | `get_sibling_prefix_escape` | CVE-2023-45278 | 🔵 fixed later | in-scope | — | 10mo | read | ran | – | [dossier](reports/yamcs__yamcs_CVE-2023-45278_5.8.6__get_sibling_prefix_escape.md) |
| `yamcs__yamcs` | `put_sibling_prefix_escape` | CVE-2023-45278 | 🔵 fixed later | in-scope | — | 10mo | read | ran | – | [dossier](reports/yamcs__yamcs_CVE-2023-45278_5.8.6__put_sibling_prefix_escape.md) |
| `gdraheim__zziplib` | `truncated_local_header_extras_oob_read` | CVE-2017-5975 | ⚪ superseded | adjacent | — | — | read | ran | – | [dossier](reports/gdraheim__zziplib_CVE-2017-5975_3a4ffcdd7870__truncated_local_header_extras_oob_read.md) |
| `git__binutils-gdb` | `opcode_base_zero_line_loop` | CVE-2017-15025 | ⚪ superseded | in-scope | — | — | read | ran | ctrl | [dossier](reports/git__binutils-gdb_CVE-2017-15025_515f23e63c00__opcode_base_zero_line_loop.md) |
| `vadz__libtiff` | `pixarlog_encode_tbuf_oob` | CVE-2016-5314 | ⚪ superseded | adjacent | — | — | read | ran | ctrl | [dossier](reports/vadz__libtiff_CVE-2016-5314_c421b993abe1__pixarlog_encode_tbuf_oob.md) |
| `vadz__libtiff` | `tile_9spp_readloop_oob` | CVE-2016-5321 | ⚪ superseded | in-scope | — | — | read | ran | – | [dossier](reports/vadz__libtiff_CVE-2016-5321_0ba5d8814a17__tile_9spp_readloop_oob.md) |
| `xwiki__xwiki-rendering` | `allowed_data_prefix_bypass_map` | CVE-2023-37908 | ⚪ superseded | adjacent | — | — | read | ran | – | [dossier](reports/xwiki__xwiki-rendering_CVE-2023-37908_14.10.3__allowed_data_prefix_bypass_map.md) |
| `xwiki__xwiki-rendering` | `allowed_data_prefix_bypass_sax` | CVE-2023-37908 | ⚪ superseded | adjacent | — | — | read | ran | – | [dossier](reports/xwiki__xwiki-rendering_CVE-2023-37908_14.10.3__allowed_data_prefix_bypass_sax.md) |

## Closed later by upstream itself — 30 PoVs

Upstream itself later closed the path the PoV drives. The lag between the official CVE fix and that later commit is the detection-lead measurement.

| project · PoV | lag | corroboration | detail |
|---|---|---|---|
| `asf__cxf` · `stylesheet_pathinfo` | 3.9y | explicit — 'Escape the services listing stylesheet path (#694)'; the diff is exactly this.styleSheet… | [dossier](reports/asf__cxf_CVE-2016-6812_3.0.11__stylesheet_pathinfo.md) |
| `asf__cxf` · `stylesheet_pathinfo` | 9mo | explicit — same commit and message as the CVE-2016-6812 twin; the official fix a02e96ba ('Make sure … | [dossier](reports/asf__cxf_CVE-2019-17573_3.2.11__stylesheet_pathinfo.md) |
| `codehaus-plexus__plexus-archiver` · `shared_prefix_tar` | 4.9y | explicit — 'Fix path traversal vulnerability ... /opt/directory starts with /opt/dir although it is … | [dossier](reports/codehaus-plexus__plexus-archiver_CVE-2018-1002200_3.5__shared_prefix_tar.md) |
| `codehaus-plexus__plexus-archiver` · `shared_prefix_zip` | 4.9y | explicit — 'Fix path traversal vulnerability ... /opt/directory starts with /opt/dir although it is … | [dossier](reports/codehaus-plexus__plexus-archiver_CVE-2018-1002200_3.5__shared_prefix_zip.md) |
| `codehaus-plexus__plexus-utils` · `residual_1_shared_prefix_sibling` | 9.5y | STRONGEST IN THE CORPUS — this residual gap received its own CVE: CVE-2025-67030 / GHSA-6fmv-xxpf-w3… | [dossier](reports/codehaus-plexus__plexus-utils_CVE-2022-4244_3.0.23__residual_1_shared_prefix_sibling.md) |
| `dromara__hutool` · `residual_fileapi_sibling_prefix` | 4.8y | silent at commit level, public in the tracker — both commit messages are only 'fix a defect in the F… | [dossier](reports/dromara__hutool_CVE-2018-17297_4.1.11__residual_fileapi_sibling_prefix.md) |
| `dromara__hutool` · `residual_unzip_sibling_prefix` | 4.8y | silent at commit level, public in the tracker — both commit messages are only 'fix a defect in the F… | [dossier](reports/dromara__hutool_CVE-2018-17297_4.1.11__residual_unzip_sibling_prefix.md) |
| `gdraheim__zziplib` · `zip64_truncated_extra_block_oob_read` | — | the commit message is the bare string 'CVE-2017-5974' — filed under a different CVE, but the diff is… | [dossier](reports/gdraheim__zziplib_CVE-2017-5976_3a4ffcdd7870__zip64_truncated_extra_block_oob_read.md) |
| `gnome__libxml2` · `snprintf_element_content_null_deref` | — | verbatim — 'Propagate error in xmlParseElementChildrenContentDeclPriv ... Otherwise, struct xmlEleme… | [dossier](reports/gnome__libxml2_CVE-2017-5969_362b3229__snprintf_element_content_null_deref.md) |
| `libming__libming` · `bitrate_table_oob_read` | — | verbatim, and it names its own CVE — 'Fix global buffer overflow in printMP3Headers ... bitrate_idx … | [dossier](reports/libming__libming_CVE-2016-9264_cc6a386__bitrate_table_oob_read.md) |
| `nahsra__antisamy` · `residual_livelist_html_xmp_anchor_javascript` | 13d | explicit — commit message: 'Fix child node removal on style tag processing' | [dossier](reports/nahsra__antisamy_CVE-2022-28367_1.6.5__residual_livelist_html_xmp_anchor_javascript.md) |
| `nahsra__antisamy` · `residual_livelist_xhtml_xmp_script` | 13d | explicit — commit message: 'Fix child node removal on style tag processing' | [dossier](reports/nahsra__antisamy_CVE-2022-28367_1.6.5__residual_livelist_xhtml_xmp_script.md) |
| `skyrpex__potrace` · `res_bmp_coltable_ncolors_oob` | — | verbatim, potrace ChangeLog v1.13 — '(2015/07/18) PS1 - fixed heap overflows, null pointer dereferen… | [dossier](reports/skyrpex__potrace_CVE-2013-7437_189777a2bd50__res_bmp_coltable_ncolors_oob.md) |
| `solon` · `symlink_follow_escape` | 1.5y | verbatim and deliberate — 'fix solon-web-staticfiles path security issue (GHSA-mmhm-jhrm-7xp9)' | [dossier](reports/solon_CVE-2025-1584_v3.0.8__symlink_follow_escape.md) |
| `solon` · `trailing_parent_dir_escape` | 1.5y | verbatim and deliberate — 'fix solon-web-staticfiles path security issue (GHSA-mmhm-jhrm-7xp9)' | [dossier](reports/solon_CVE-2025-1584_v3.0.8__trailing_parent_dir_escape.md) |
| `srikanth-lingala__zip4j` · `residual_1_shared_prefix_file` | 8mo | explicit — '#133 Fix for zip slip when file name is similar to directory extracted to'; third-party … | [dossier](reports/srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2__residual_1_shared_prefix_file.md) |
| `srikanth-lingala__zip4j` · `residual_2_shared_prefix_directory` | 8mo | explicit — '#133 Fix for zip slip when file name is similar to directory extracted to'; third-party … | [dossier](reports/srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2__residual_2_shared_prefix_directory.md) |
| `vadz__libtiff` · `contigtiles2separatestrips_oob` | — | incidental by message ('fix heap buffer overflow in tiffcp (#278)'), but GitLab issue #278 is titled… | [dossier](reports/vadz__libtiff_CVE-2017-5225_393881da1a7f__contigtiles2separatestrips_oob.md) |
| `vadz__libtiff` · `refblackwhite_default_bps64_shift` | — | incidental — 'Harden integer size and offset calculations in libtiff, tools, and contrib', a 33-file… | [dossier](reports/vadz__libtiff_CVE-2017-7601_3144e57770c1__refblackwhite_default_bps64_shift.md) |
| `vadz__libtiff` · `ojpeg_readheaderinfo_zero_subsampling_fpe` | — | verbatim — 'OJPEG: fix integer division by zero on corrupted subsampling factors. Fixes oss-fuzz iss… | [dossier](reports/vadz__libtiff_bugzilla-2611_9a72a69e035e__ojpeg_readheaderinfo_zero_subsampling_fpe.md) |
| `yamcs__yamcs` · `bucket_name_traversal_read` | 12mo | incidental, by removal — 92edb5f2 'Add bucket provider mechanism' deletes the class; no commit ever … | [dossier](reports/yamcs__yamcs_CVE-2023-45277_5.8.6__bucket_name_traversal_read.md) |
| `yamcs__yamcs` · `delete_sibling_prefix` | 10mo | incidental — 4d41784a is Allow symlinks in fs buckets #919; its companion test adds only a symlink t… | [dossier](reports/yamcs__yamcs_CVE-2023-45277_5.8.6__delete_sibling_prefix.md) |
| `yamcs__yamcs` · `find_sibling_prefix` | 10mo | incidental — 4d41784a is Allow symlinks in fs buckets #919; its companion test adds only a symlink t… | [dossier](reports/yamcs__yamcs_CVE-2023-45277_5.8.6__find_sibling_prefix.md) |
| `yamcs__yamcs` · `get_sibling_prefix` | 10mo | incidental — 4d41784a is Allow symlinks in fs buckets #919; its companion test adds only a symlink t… | [dossier](reports/yamcs__yamcs_CVE-2023-45277_5.8.6__get_sibling_prefix.md) |
| `yamcs__yamcs` · `put_sibling_prefix` | 10mo | incidental — 4d41784a is Allow symlinks in fs buckets #919; its companion test adds only a symlink t… | [dossier](reports/yamcs__yamcs_CVE-2023-45277_5.8.6__put_sibling_prefix.md) |
| `yamcs__yamcs` · `bucket_name_traversal` | 12mo | incidental, by removal — see the CVE-2023-45277 twin | [dossier](reports/yamcs__yamcs_CVE-2023-45278_5.8.6__bucket_name_traversal.md) |
| `yamcs__yamcs` · `delete_sibling_prefix_escape` | 10mo | incidental — 4d41784a is Allow symlinks in fs buckets #919; its companion test adds only a symlink t… | [dossier](reports/yamcs__yamcs_CVE-2023-45278_5.8.6__delete_sibling_prefix_escape.md) |
| `yamcs__yamcs` · `find_sibling_prefix_escape` | 10mo | incidental — 4d41784a is Allow symlinks in fs buckets #919; its companion test adds only a symlink t… | [dossier](reports/yamcs__yamcs_CVE-2023-45278_5.8.6__find_sibling_prefix_escape.md) |
| `yamcs__yamcs` · `get_sibling_prefix_escape` | 10mo | incidental — 4d41784a is Allow symlinks in fs buckets #919; its companion test adds only a symlink t… | [dossier](reports/yamcs__yamcs_CVE-2023-45278_5.8.6__get_sibling_prefix_escape.md) |
| `yamcs__yamcs` · `put_sibling_prefix_escape` | 10mo | incidental — 4d41784a is Allow symlinks in fs buckets #919; its companion test adds only a symlink t… | [dossier](reports/yamcs__yamcs_CVE-2023-45278_5.8.6__put_sibling_prefix_escape.md) |

## Never shipped open — an artifact of the chosen baseline — 6 PoVs

No released tree ever carried the gap: the benchmark's chosen "official fix" commit is not what upstream shipped. Valid instruments; no upstream-miss claim.

| project · PoV | lag | corroboration | detail |
|---|---|---|---|
| `gdraheim__zziplib` · `truncated_local_header_extras_oob_read` | — | verbatim — 'remember extra_block length / check min and max sizes / ... CVE-2017-5974 / CVE-2017-597… | [dossier](reports/gdraheim__zziplib_CVE-2017-5975_3a4ffcdd7870__truncated_local_header_extras_oob_read.md) |
| `git__binutils-gdb` · `opcode_base_zero_line_loop` | — | verbatim — 'PR22204, Lack of DW_LNE_end_sequence causes infinite loop / PR 22204 / * dwarf2.c (decod… | [dossier](reports/git__binutils-gdb_CVE-2017-15025_515f23e63c00__opcode_base_zero_line_loop.md) |
| `vadz__libtiff` · `pixarlog_encode_tbuf_oob` | — | verbatim — 'Fix write buffer overflow in PixarLogEncode if more input samples are provided than expe… | [dossier](reports/vadz__libtiff_CVE-2016-5314_c421b993abe1__pixarlog_encode_tbuf_oob.md) |
| `vadz__libtiff` · `tile_9spp_readloop_oob` | — | verbatim — 'tools/tiffcrop.c: Avoid access outside of stack allocated array on a tiled separate TIFF… | [dossier](reports/vadz__libtiff_CVE-2016-5321_0ba5d8814a17__tile_9spp_readloop_oob.md) |
| `xwiki__xwiki-rendering` · `allowed_data_prefix_bypass_map` | — | verbatim — 'XCOMMONS-2606: Properly validate data attributes in SecureHTMLElementSanitizer'; deliber… | [dossier](reports/xwiki__xwiki-rendering_CVE-2023-37908_14.10.3__allowed_data_prefix_bypass_map.md) |
| `xwiki__xwiki-rendering` · `allowed_data_prefix_bypass_sax` | — | verbatim — 'XCOMMONS-2606: Properly validate data attributes in SecureHTMLElementSanitizer'; deliber… | [dossier](reports/xwiki__xwiki-rendering_CVE-2023-37908_14.10.3__allowed_data_prefix_bypass_sax.md) |

## What this report cannot say

- **`ran` is not `ctrl`.** A PoV that reproduces on both baseline trees has an independently re-proved certification, and nothing more.
- **An `errored` execution is evidence for nothing.** A PoV written against a 2018 revision usually will not build against a 2024 one — the per-CVE Docker image pins an old toolchain — so the control reports `inconclusive`, never `blocked`.
- **Open at head ≠ exploitable.** Before any disclosure: attacker-controlled input must reach the sink through a public entry point, preconditions must be realistic, and a trust boundary must actually be crossed. Containers here run as root; a gap needing root is not a finding.
- **A synthetic tree is not a shipped release.** Certification runs against `buggy_commit + official_fix.patch`, which never shipped.

