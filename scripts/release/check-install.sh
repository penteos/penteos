#!/bin/sh
# Inside a clean container of one distribution: install Penteos the way a user would, run its core
# end to end, then open the whole app on a virtual screen.
#   check-install.sh <deb|dnf|yum|zypper|appimage>      (the packages are in /pkg)
set -eu
FAMILY="$1"
# The package for this machine's architecture (x86_64 or arm64), named as electron-builder names it.
case "$(uname -m)" in
  aarch64|arm64) DEB=arm64; RPM=aarch64; APPIMAGE=arm64 ;;
  *) DEB=amd64; RPM=x86_64; APPIMAGE=x86_64 ;;
esac
export DEBIAN_FRONTEND=noninteractive
APP=/opt/Penteos
case "$FAMILY" in
  deb)
    # Debian 11 left the mirrors when its support ended (2026-08): its packages live in the archive.
    if grep -q '^ID=debian' /etc/os-release && grep -q '^VERSION_ID="11"' /etc/os-release; then
      sed -i 's|deb.debian.org/debian-security|archive.debian.org/debian-security|; s|deb.debian.org/debian|archive.debian.org/debian|' /etc/apt/sources.list 2>/dev/null || true
      echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive
    fi
    apt-get -o Acquire::Retries=5 update -qq
    # Penteos and its declared dependencies first: this is what we validate.
    apt-get -o Acquire::Retries=5 install -y -qq --fix-missing /pkg/penteos-*-$DEB.deb >/dev/null
    # Test tools apart: a stale base-image mirror (old Debian) may 404 these; not Penteos's concern.
    apt-get -o Acquire::Retries=5 install -y -qq --fix-missing xvfb python3 procps xz-utils passwd desktop-file-utils >/dev/null \
      || echo "WARN: test tools missing (container mirror); trying the GUI anyway"
    ;;
  dnf|yum)
    # The .rpm asks for its libraries by file name: dnf brings them; only the test tools go here.
    $FAMILY install -y -q xorg-x11-server-Xvfb xorg-x11-xauth python3 procps-ng util-linux dejavu-sans-fonts xz shadow-utils desktop-file-utils >/dev/null
    $FAMILY install -y -q /pkg/penteos-*-$RPM.rpm >/dev/null
    ;;
  zypper)
    # Container images come without fonts (a desktop always has them): Chromium cannot draw without one.
    zypper -q -n install xorg-x11-server-Xvfb python3 procps util-linux dejavu-fonts xz shadow desktop-file-utils >/dev/null
    zypper -q -n install --allow-unsigned-rpm /pkg/penteos-*-$RPM.rpm >/dev/null
    ;;
  appimage)
    # A full upgrade with the install: Arch does not support partial upgrades (-Sy), and a stale
    # image against today's repositories can conflict (openssl split into openssl-3, 2026-11).
    pacman -Syu --noconfirm --needed gtk3 nss alsa-lib libxss libdrm mesa xorg-server-xvfb xorg-xauth python util-linux procps-ng ttf-dejavu >/dev/null
    cp /pkg/penteos-*-$APPIMAGE.AppImage /tmp/penteos.AppImage
    chmod +x /tmp/penteos.AppImage
    # No FUSE inside a container: the AppImage extracts itself (what it also does on a machine without FUSE).
    (cd /tmp && ./penteos.AppImage --appimage-extract >/dev/null)
    APP=/tmp/squashfs-root
    ;;
  *) echo "unknown family: $FAMILY"; exit 2 ;;
esac
echo "== installed: $(ls -d "$APP")"

# The menu entry and the icon, as GNOME, KDE and the rest read them (packages only; the AppImage
# adds its own on first start).
if [ "$FAMILY" != appimage ]; then
  entry=/usr/share/applications/penteos.desktop
  [ -f "$entry" ] || { echo "menu entry missing ($entry)"; exit 7; }
  grep -q '^StartupWMClass=penteos$' "$entry" || { echo "the menu entry does not name the window (StartupWMClass=penteos)"; cat "$entry"; exit 7; }
  grep -q '^Icon=penteos$' "$entry" || { echo "the menu entry does not use the penteos icon"; exit 7; }
  ls /usr/share/icons/hicolor/256x256/apps/penteos.png >/dev/null 2>&1 || { echo "the 256x256 icon is missing (the hicolor theme has no 1024x1024)"; ls -R /usr/share/icons/hicolor | grep -i penteos; exit 7; }
  if command -v desktop-file-validate >/dev/null 2>&1; then desktop-file-validate "$entry" || { echo "invalid menu entry"; exit 7; }; fi
  # The AppArmor profile (Ubuntu 24.04+, openSUSE) must cover the real binary, not only the launcher.
  if [ -f /etc/apparmor.d/penteos ]; then grep -q 'penteos.bin' /etc/apparmor.d/penteos || { echo "the AppArmor profile does not cover penteos.bin"; cat /etc/apparmor.d/penteos; exit 7; }; fi
  [ -f "$APP/resources/apparmor-profile" ] && { grep -q 'penteos.bin' "$APP/resources/apparmor-profile" || { echo "the package's AppArmor profile does not cover penteos.bin"; exit 7; }; }
  echo "menu entry, icon and AppArmor profile: ok"
fi
command -v Xvfb >/dev/null || { echo "no Xvfb"; exit 3; }

# A virtual screen: the agents' browser (Penteos's own Chromium) and the app need one.
Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
sleep 2
export DISPLAY=:99

echo "== core end to end"
# Containers run as root: the app turns Chromium's sandbox off by itself (this verifies it).
ELECTRON_RUN_AS_NODE=1 "$APP/penteos" /pkg/e2e-core.mjs "$APP" --offline

echo "== the whole app on a virtual screen"
DATA="$(mktemp -d)"
# As root the app turns Chromium's sandbox off by itself; this verifies it opens anyway.
PENTEOS_DATA_DIR="$DATA" timeout 45 "$APP/penteos" >/tmp/gui.log 2>&1 || code=$?
if [ "${code:-0}" -ne 124 ]; then echo "the app closed by itself (code ${code:-0})"; tail -20 /tmp/gui.log; exit 4; fi
[ -f "$DATA/core.json" ] || [ -d "$DATA/engagements" ] || { echo "the app opened but the core did not start"; tail -20 /tmp/gui.log; exit 5; }
echo "GUI OK"

# The tool box as a normal user, the way people use Penteos: verified tools installed without root
#. Desktops always have xz (their package manager needs it); the
# test images get it above.
echo "== tools as a normal user (no root)"
useradd -m pentester >/dev/null 2>&1 || true
id pentester >/dev/null 2>&1 || { echo "could not create the test user"; exit 6; }
runuser -u pentester -- env HOME=/home/pentester DISPLAY=:99 ELECTRON_RUN_AS_NODE=1 "$APP/penteos" /pkg/e2e-core.mjs "$APP" --offline --only-tools
echo "TOOLS OK"
