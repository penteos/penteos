# Release builds for Linux: every package from one image.
# The terminal's native module is compiled with zig against glibc 2.28, so the packages run on
# Debian 10, RHEL/Rocky 8, Ubuntu 20.04 and everything newer - also for arm64, from an x64 machine.
FROM node:24-bookworm
ARG ZIG=0.13.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends rpm fakeroot xz-utils python3 make libarchive-tools squashfs-tools ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://ziglang.org/download/${ZIG}/zig-linux-x86_64-${ZIG}.tar.xz" | tar -xJ -C /opt \
 && ln -s /opt/zig-linux-x86_64-${ZIG}/zig /usr/local/bin/zig \
 && for a in x64:x86_64 arm64:aarch64; do \
      n=${a%%:*}; t=${a##*:}; \
      printf '#!/bin/sh\nexec zig cc -target %s-linux-gnu.2.28 "$@"\n' "$t" > /usr/local/bin/penteos-cc-$n; \
      printf '#!/bin/sh\nexec zig c++ -target %s-linux-gnu.2.28 "$@"\n' "$t" > /usr/local/bin/penteos-cxx-$n; \
      chmod +x /usr/local/bin/penteos-cc-$n /usr/local/bin/penteos-cxx-$n; \
    done \
 && corepack enable
ENV PENTEOS_CC_x64=penteos-cc-x64 PENTEOS_CXX_x64=penteos-cxx-x64 \
    PENTEOS_CC_arm64=penteos-cc-arm64 PENTEOS_CXX_arm64=penteos-cxx-arm64
WORKDIR /src
