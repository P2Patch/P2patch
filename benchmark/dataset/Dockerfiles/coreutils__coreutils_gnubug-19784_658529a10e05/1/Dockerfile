FROM ubuntu:22.04 AS builder
LABEL org.opencontainers.image.source="https://github.com/coreutils/coreutils"
LABEL org.opencontainers.image.description="Build environment for coreutils__coreutils_gnubug-19784_658529a10e05 (1)"
LABEL org.opencontainers.image.title="coreutils__coreutils_gnubug-19784_658529a10e05:1"
LABEL com.dataset.cve_id="gnubug-19784"
LABEL com.dataset.cwe_id="CWE-125"
LABEL com.dataset.cwe_name="Out-of-bounds Read"
LABEL com.dataset.project_slug="coreutils__coreutils_gnubug-19784_658529a10e05"
LABEL com.dataset.status="success"
WORKDIR /workspace
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates build-essential autoconf automake libtool pkg-config \
      gperf gettext autopoint texinfo bison flex rsync perl python3 xz-utils patch m4 wget \
      && rm -rf /var/lib/apt/lists/*

ARG GIT_URL=https://github.com/coreutils/coreutils
ARG GIT_COMMIT=658529a10e05d06524d5f591a08f04c04159b4cc
RUN set -eux; \
    mkdir repo && cd repo && git init -q && git remote add origin "$GIT_URL"; \
    (git fetch --depth 1 origin "$GIT_COMMIT" && git checkout -q FETCH_HEAD) || ( \
      cd /workspace && rm -rf repo; \
      for i in 1 2 3 4 5 6; do \
        git clone "$GIT_URL" repo && break; \
        echo "clone attempt $i failed, retrying after backoff..." >&2; \
        rm -rf repo; sleep $((i * 60)); \
      done; \
      cd repo; git checkout "$GIT_COMMIT" \
    ); \
    cd /workspace/repo; \
    git config submodule.gnulib.url https://git.savannah.gnu.org/git/gnulib.git; \
    git submodule update --init gnulib

# coreutils ships no pre-generated `configure` in git -- ./bootstrap pulls in
# gnulib (submodule pinned above, URL rewritten from git:// since Savannah's
# git:// daemon is retired) and runs autoreconf. --skip-po avoids a network
# fetch of translations we don't need. FORCE_UNSAFE_CONFIGURE=1 because this
# build runs as root inside the container (coreutils' own configure refuses
# root by default as a footgun guard, irrelevant here).
# This bug is in the build-time host tool src/make-prime-list (generates
# src/primes.h); it is not one of the installed end-user coreutils binaries.
# Build everything rather than just `src/make-prime-list`: coreutils includes
# gnulib non-recursively (build-aux/prefix-gnulib-mk rewrites every
# lib/gnulib.mk target with a `lib/` prefix), and the generated headers are
# BUILT_SOURCES, which automake only makes as part of `all`. Naming a single
# program target skips them, and on a fresh tree there are no depfiles to pull
# them in implicitly.
# The vendored gnulib (2016) predates glibc 2.28, which stopped exposing the
# libio internals it probes for. Its GNU-libc branch is gated on
# `#if defined _IO_ftrylockfile` in eight lib/*.c files; that macro is now
# private, so all eight fall through to `#error "Please port ... to your
# platform!"`. glibc still defines _IO_EOF_SEEN (bits/types/struct_FILE.h) and
# still has every struct field the branch touches, so re-pointing the probe at
# it restores the correct code path -- this is not just silencing the error.
# The four flag bits that branch uses went private in the same release and are
# re-supplied below at their glibc values (libio/libio.h). Note the widely
# quoted one-line version of this fix only restores _IO_IN_BACKUP; freading.c
# also needs _IO_NO_READS/_IO_NO_WRITES/_IO_CURRENTLY_PUTTING.
#
# src/make-prime-list is itself gnubug-19784's vulnerable code (a
# heap-buffer-overflow in xalloc, make-prime-list.c:163/214) -- the POV runs
# the ASan-instrumented binary directly against a crafted limit. But `make
# all` also invokes it once, uninstrumented, as a BUILT_SOURCES rule to
# generate src/primes.h, and an ASan build aborts on that internal
# invocation before the product ever finishes compiling -- the build cannot
# reach the vulnerability without first tripping over it. So primes.h is
# generated in an initial non-ASan pass, then locked with `--assume-old` so
# the ASan-reconfigured `make all` does not try to regenerate it (which
# would relink an ASan make-prime-list and re-trigger the same crash).
RUN set -eux; cd /workspace/repo; \
    FORCE_UNSAFE_CONFIGURE=1 ./bootstrap --skip-po && \
    sed -i 's/_IO_ftrylockfile/_IO_EOF_SEEN/g' lib/*.c && \
    printf '#ifndef _IO_IN_BACKUP\n# define _IO_IN_BACKUP 0x0100\n#endif\n#ifndef _IO_NO_READS\n# define _IO_NO_READS 0x0004\n#endif\n#ifndef _IO_NO_WRITES\n# define _IO_NO_WRITES 0x0008\n#endif\n#ifndef _IO_CURRENTLY_PUTTING\n# define _IO_CURRENTLY_PUTTING 0x0800\n#endif\n' >> lib/stdio-impl.h && \
    FORCE_UNSAFE_CONFIGURE=1 ./configure CFLAGS="-g -O0 -Wno-error -fcommon" CXXFLAGS="-g -O0 -Wno-error -fcommon" && \
    make -j"$(nproc)" src/primes.h && \
    FORCE_UNSAFE_CONFIGURE=1 ./configure \
      CFLAGS="-fsanitize=address -g -O0 -Wno-error -fcommon" \
      CXXFLAGS="-fsanitize=address -g -O0 -Wno-error -fcommon" \
      LDFLAGS="-fsanitize=address" && \
    make -j"$(nproc)" --assume-old=src/primes.h

FROM scratch AS artifact
COPY --from=builder /workspace/repo /repo
