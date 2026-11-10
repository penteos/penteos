#!/bin/sh
# Penteos installer for Linux and macOS.
#
#   curl -fsSL <url>/install.sh | sh                 # the right package for this system
#   curl -fsSL <url>/install.sh | sh -s -- --appimage  # Linux, no root: the AppImage in ~/.local/bin
#
# Debian/Ubuntu/Kali/Mint → .deb (apt), Fedora/RHEL/Rocky/openSUSE → .rpm (dnf/yum/zypper),
# anything else (Arch, Gentoo, Void…) or no root → the AppImage, which needs nothing installed.
# macOS → Penteos.app in /Applications (or ~/Applications), no password; downloaded this way it
# opens without Gatekeeper's warning, and updates itself from then on.
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

OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
  # The chip itself: under Rosetta, uname -m says x86_64 on an Apple Silicon Mac.
  if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ]; then MAC_ARCH=arm64; else MAC_ARCH=x64; fi
else
  case "$(uname -m)" in
    x86_64|amd64) DEB_ARCH=amd64; RPM_ARCH=x86_64; IMG_ARCH=x86_64 ;;
    aarch64|arm64) DEB_ARCH=arm64; RPM_ARCH=aarch64; IMG_ARCH=arm64 ;;
    *) fail "unsupported architecture $(uname -m) (x86_64 or arm64 only)" ;;
  esac
fi
# version_ge A B: A >= B, part by part as numbers (12 = 12.0, 14.10 > 14.9).
version_ge() { awk -v a="$1" -v b="$2" 'BEGIN { n = split(a, x, "."); m = split(b, y, "."); for (i = 1; i <= (n > m ? n : m); i++) { if ((x[i] + 0) > (y[i] + 0)) exit 0; if ((x[i] + 0) < (y[i] + 0)) exit 1 } exit 0 }'; }
# SHA-256 of a file: sha256sum on Linux, shasum on macOS.
if need sha256sum; then sha256() { sha256sum "$1" | cut -d' ' -f1; }
else sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi

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
  actual="$(sha256 "$TMP/$file")"
  [ "$expected" = "$actual" ] || fail "the checksum of $file does not match: the download is damaged or was tampered with"
}

# macOS: the app goes to /Applications when this user may write there (admins can), else to
# ~/Applications; replaced whole, with nothing to ask.
if [ "$OS" = "Darwin" ]; then
  file="penteos-$VERSION-mac-$MAC_ARCH.zip"
  download "$file"
  # ditto keeps the app's links and signature; unzip can break both.
  ditto -x -k "$TMP/$file" "$TMP/app"
  [ -d "$TMP/app/Penteos.app" ] || fail "the download has no Penteos.app inside"
  min=$(/usr/libexec/PlistBuddy -c "Print :LSMinimumSystemVersion" "$TMP/app/Penteos.app/Contents/Info.plist" 2>/dev/null || echo "")
  have=$(sw_vers -productVersion)
  if [ -n "$min" ] && ! version_ge "$have" "$min"; then
    fail "this Penteos needs macOS $min or newer; this Mac has $have"
  fi
  if [ -w /Applications ]; then dest=/Applications; else dest="$HOME/Applications"; mkdir -p "$dest"; fi
  if pgrep -x Penteos >/dev/null 2>&1; then say "Penteos is open: the new version is used the next time it starts"; fi
  rm -rf "$dest/Penteos.app.old"
  [ -d "$dest/Penteos.app" ] && mv "$dest/Penteos.app" "$dest/Penteos.app.old"
  mv "$TMP/app/Penteos.app" "$dest/Penteos.app"
  rm -rf "$dest/Penteos.app.old"
  # Downloaded with curl it carries no quarantine; cleared anyway, in case the zip came another way.
  xattr -dr com.apple.quarantine "$dest/Penteos.app" 2>/dev/null || true
  say "installed in $dest/Penteos.app"
  say "done: Penteos $VERSION. Open it from Launchpad or with: open -a Penteos"
  exit 0
fi

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
