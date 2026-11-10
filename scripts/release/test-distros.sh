#!/bin/sh
# Every package against a set of clean distributions, one container at a time, each image removed
# when done.
#   test-distros.sh <folder with the packages and e2e-core.mjs> [image …]
set -u
PKG="$1"; shift
SRC="$(cd "$(dirname "$0")" && pwd)"
cp "$SRC/e2e-core.mjs" "$SRC/check-install.sh" "$PKG/"
DEFAULT="ubuntu:20.04=deb ubuntu:22.04=deb ubuntu:24.04=deb debian:11=deb debian:12=deb kalilinux/kali-rolling=deb fedora:40=dnf fedora:41=dnf rockylinux:8=dnf rockylinux:9=dnf opensuse/leap:15.6=zypper opensuse/tumbleweed=zypper archlinux:latest=appimage"
MATRIX="${*:-$DEFAULT}"
RESULTS=""
for item in $MATRIX; do
  image="${item%%=*}"; family="${item##*=}"
  echo "################ $image ($family)"
  if nice -n 15 docker run --rm --cpus 2 --memory 4g -v "$PKG":/pkg:ro "$image" sh /pkg/check-install.sh "$family" > "$PKG/test-$(echo "$image" | tr '/:' '__').log" 2>&1; then
    RESULTS="$RESULTS\n✓ $image"
  else
    RESULTS="$RESULTS\n✗ $image  (see test-$(echo "$image" | tr '/:' '__').log)"
  fi
  tail -6 "$PKG/test-$(echo "$image" | tr '/:' '__').log"
  docker rmi -f "$image" >/dev/null 2>&1 || true
done
printf "\n== result$RESULTS\n"
