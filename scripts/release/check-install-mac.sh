#!/bin/sh
# macOS: installs Penteos the way the README says (the one-line installer, as a normal user), and
# checks what Linux's check-install.sh checks: the signature, the core end to end, the whole app
# opening, and the tool box without root.
#   sh scripts/release/check-install-mac.sh <folder with install.sh, VERSION, SHA256SUMS and the .zip files>
set -eu
PKG="$(cd "$1" && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== install (curl | sh, as the README says)"
PENTEOS_RELEASES="file://$PKG" sh "$PKG/install.sh"
APP=/Applications/Penteos.app
[ -d "$APP" ] || APP="$HOME/Applications/Penteos.app"
[ -x "$APP/Contents/MacOS/Penteos" ] || { echo "Penteos.app is not where the installer said"; exit 2; }
echo "installed: $APP ($(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist"), needs macOS $(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$APP/Contents/Info.plist" 2>/dev/null || echo '?'))"

echo "== signature (ad hoc, every nested binary)"
codesign --verify --deep --strict --verbose=2 "$APP"
# No quarantine: it would make Gatekeeper refuse an app that is not notarized.
if xattr -r "$APP" 2>/dev/null | grep -q com.apple.quarantine; then echo "the installed app carries the quarantine flag"; exit 3; fi

echo "== core end to end"
ELECTRON_RUN_AS_NODE=1 "$APP/Contents/MacOS/Penteos" "$HERE/e2e-core.mjs" "$APP" --offline

echo "== the whole app"
DATA="$(mktemp -d)"
PENTEOS_DATA_DIR="$DATA" "$APP/Contents/MacOS/Penteos" >/tmp/gui.log 2>&1 &
pid=$!
sleep 40
if ! kill -0 "$pid" 2>/dev/null; then echo "the app closed by itself"; tail -30 /tmp/gui.log; exit 4; fi
[ -f "$DATA/core.json" ] || [ -d "$DATA/engagements" ] || { echo "the app opened but the core did not start"; tail -30 /tmp/gui.log; kill "$pid"; exit 5; }
kill "$pid"
sleep 3
# Nothing it started may outlive it (the core, tools, the agents' browser).
if pgrep -f "$APP/Contents" >/dev/null; then echo "processes outlived the app:"; pgrep -fl "$APP/Contents"; exit 6; fi
echo "GUI OK"

echo "== tools without root"
ELECTRON_RUN_AS_NODE=1 "$APP/Contents/MacOS/Penteos" "$HERE/e2e-core.mjs" "$APP" --offline --only-tools
echo "TOOLS OK"
