#!/bin/sh
# Penteos installer for Linux.
#
#   curl -fsSL <url>/install.sh | sh                 # the right package for this distribution
#   curl -fsSL <url>/install.sh | sh -s -- --appimage  # no root: the AppImage in ~/.local/bin
#
# Debian/Ubuntu/Kali/Mint → .deb (apt), Fedora/RHEL/Rocky/openSUSE → .rpm (dnf/yum/zypper),
# anything else (Arch, Gentoo, Void…) or no root → the AppImage, which needs nothing installed.
# Every download is checked against the release's SHA256SUMS before anything is installed.
set -eu

BASE="${PENTEOS_RELEASES:-https://github.com/penteos/penteos/releases/latest/download}"
MODE="auto"
for arg in "$@"; do
  case "$arg" in
    --appimage) MODE="appimage" ;;
    --deb) MODE="deb" ;;
    --rpm) MODE="rpm" ;;
    -h|--help) sed -n '2,9p' "$0" 2>/dev/null || true; exit 0 ;;
  esac
done

# The banner: PENTEOS in the brand's colours (violet to torch orange), only on a terminal.
banner() {
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then c() { printf '\033[38;5;%sm%s\033[0m\n' "$1" "$2"; }; else c() { printf '%s\n' "$2"; }; fi
  printf '\n'
  c 141 '   ____   _____  _   _  _____  _____   ___   ____'
  c 135 '  |  _ \ | ____|| \ | ||_   _|| ____| / _ \ / ___|'
  c 171 '  | |_) ||  _|  |  \| |  | |  |  _|  | | | |\___ \'
  c 209 '  |  __/ | |___ | |\  |  | |  | |___ | |_| | ___) |'
  c 208 '  |_|    |_____||_| \_|  |_|  |_____| \___/ |____/'
  printf '\n'
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then printf '  \033[38;5;208m>*\033[0m \033[1mthe AI pentest workbench\033[0m  \033[2m%s\033[0m\n\n' "$1"; else printf '  >* the AI pentest workbench  %s\n\n' "$1"; fi
}
say() { printf '\033[1;35mpenteos\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mpenteos\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1; }

if need curl; then fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif need wget; then fetch() { wget -q -O "$2" "$1"; }
else fail "curl or wget is needed to download"; fi

case "$(uname -m)" in
  x86_64|amd64) DEB_ARCH=amd64; RPM_ARCH=x86_64; IMG_ARCH=x86_64 ;;
  aarch64|arm64) DEB_ARCH=arm64; RPM_ARCH=aarch64; IMG_ARCH=arm64 ;;
  *) fail "unsupported architecture $(uname -m) (x86_64 or arm64 only)" ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fetch "$BASE/VERSION" "$TMP/VERSION" || fail "could not look up the latest version at $BASE"
VERSION="$(tr -d ' \n\r' < "$TMP/VERSION")"
banner "v$VERSION"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || fail "could not download the checksums"

# The privilege to install system packages: root, or sudo.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if need sudo; then SUDO="sudo"; elif [ "$MODE" = "auto" ]; then MODE="appimage"; fi
fi

if [ "$MODE" = "auto" ]; then
  if need apt-get && need dpkg; then MODE="deb"
  elif need dnf || need yum || need zypper; then MODE="rpm"
  else MODE="appimage"; fi
fi

download() {
  file="$1"
  say "downloading $file"
  fetch "$BASE/$file" "$TMP/$file" || fail "could not download $file"
  expected="$(grep " $file\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)"
  [ -n "$expected" ] || fail "$file is not listed in SHA256SUMS"
  actual="$(sha256sum "$TMP/$file" | cut -d' ' -f1)"
  [ "$expected" = "$actual" ] || fail "the checksum of $file does not match: the download is damaged or was tampered with"
}

case "$MODE" in
  deb)
    file="penteos-$VERSION-$DEB_ARCH.deb"
    download "$file"
    say "installing with apt (it may ask for your password)"
    $SUDO apt-get install -y "$TMP/$file"
    ;;
  rpm)
    file="penteos-$VERSION-$RPM_ARCH.rpm"
    download "$file"
    say "installing the package (it may ask for your password)"
    if need dnf; then $SUDO dnf install -y "$TMP/$file"
    elif need yum; then $SUDO yum install -y "$TMP/$file"
    else $SUDO zypper --non-interactive install --allow-unsigned-rpm "$TMP/$file"; fi
    ;;
  appimage)
    file="penteos-$VERSION-$IMG_ARCH.AppImage"
    download "$file"
    dest="${XDG_BIN_HOME:-$HOME/.local/bin}"
    mkdir -p "$dest"
    install -m 0755 "$TMP/$file" "$dest/penteos.AppImage"
    ln -sf "$dest/penteos.AppImage" "$dest/penteos"
    say "installed in $dest/penteos (it adds itself to the applications menu the first time it opens)"
    case ":$PATH:" in *":$dest:"*) ;; *) say "add $dest to your PATH to open it by typing: penteos" ;; esac
    ;;
esac

say "done: Penteos $VERSION. Open it from the applications menu or with: penteos"
