#!/bin/sh
# Penteos launcher (the executable of every Linux package; the real binary is __NAME__.bin next to
# it). It never turns Chromium's sandbox off on its own for a normal user:
#  - its desktop identity is Penteos's, whoever started it (another app's terminal says otherwise);
#  - as root, Chromium cannot start with its sandbox: --no-sandbox (the operator's decision);
#  - on Ubuntu 24.04+ only programs with an AppArmor profile may use the user namespaces the sandbox
#    needs. The .deb/.rpm bring one. An AppImage or a tar.gz asks for the password ONCE to add a
#    profile for its own file, then starts again with the sandbox on. Without that, it says what to
#    do and does not open unprotected.
here="$(dirname "$(readlink -f "$0")")"
real="$here/__NAME__.bin"
export CHROME_DESKTOP=penteos.desktop
unset GIO_LAUNCHED_DESKTOP_FILE GIO_LAUNCHED_DESKTOP_FILE_PID BAMF_DESKTOP_FILE_HINT

# Electron as plain Node (the core): no window, no sandbox question.
[ -n "${ELECTRON_RUN_AS_NODE:-}" ] && exec "$real" "$@"
[ "$(id -u)" = 0 ] && exec "$real" --no-sandbox "$@"

restricted() { [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ]; }
profiled() { label="$(cat /proc/self/attr/current 2>/dev/null)"; [ -n "$label" ] && [ "$label" != "unconfined" ]; }
suid_helper() { [ -u "$here/chrome-sandbox" ] && [ "$(stat -c %u "$here/chrome-sandbox" 2>/dev/null)" = 0 ]; }

if restricted && ! profiled && ! suid_helper; then
  # What the profile attaches to: the AppImage file when run as one, else this launcher. AppArmor
  # passes the profile on to what it starts (AppRun, this launcher, the app, the core, the browser).
  target="${APPIMAGE:-$here/__NAME__}"
  say() {
    echo "penteos: $1" >&2
    if command -v notify-send >/dev/null 2>&1; then notify-send -a Penteos "Penteos" "$1" 2>/dev/null
    elif command -v zenity >/dev/null 2>&1; then zenity --info --title=Penteos --text="$1" 2>/dev/null
    elif command -v kdialog >/dev/null 2>&1; then kdialog --title Penteos --msgbox "$1" 2>/dev/null
    fi
  }
  # Only a plain path goes into the profile (no quotes, globs or control characters).
  if printf '%s' "$target" | grep -q '["\\*?{}^[:cntrl:]]\|\[\|\]' || [ "$(printf '%s' "$target" | wc -l)" -gt 0 ]; then
    case "${LANG:-}" in
      es*) say "Este sistema restringe el aislamiento de Chromium y la ruta de Penteos no se puede usar en un perfil de AppArmor. Mueva el archivo a una carpeta sin caracteres especiales, o instale el paquete .deb o .rpm." ;;
      *) say "This system restricts Chromium's sandbox and Penteos's path cannot be used in an AppArmor profile. Move the file to a folder without special characters, or install the .deb or .rpm package." ;;
    esac
    exit 1
  fi
  if [ -z "${PENTEOS_PROFILE_TRIED:-}" ] && command -v pkexec >/dev/null 2>&1 && { [ -x /sbin/apparmor_parser ] || [ -x /usr/sbin/apparmor_parser ]; }; then
    id="$(printf '%s' "$target" | sha256sum | cut -c1-12)"
    profile="$(mktemp)"
    cat > "$profile" <<EOF
abi <abi/4.0>,
include <tunables/global>

# Added by Penteos at the operator's request: lets this copy of Penteos use Chromium's sandbox.
profile penteos-local-$id "$target" flags=(unconfined) {
  userns,
}
EOF
    if pkexec /bin/sh -c 'install -m 644 "$1" "$2" && apparmor_parser -r "$2"' penteos "$profile" "/etc/apparmor.d/penteos-local-$id"; then
      rm -f "$profile"
      # Started again so the profile applies from the first process on.
      PENTEOS_PROFILE_TRIED=1 exec "$target" "$@"
    fi
    rm -f "$profile"
  fi
  case "${LANG:-}" in
    es*) say "Este sistema (Ubuntu 24.04 o posterior) solo deja usar el aislamiento de Chromium a programas con permiso. Penteos lo pide una vez con su contraseña: abra una terminal, ejecute $target y acepte. Instalar el paquete .deb o .rpm lo resuelve también." ;;
    *) say "This system (Ubuntu 24.04 or later) only lets programs with permission use Chromium's sandbox. Penteos asks for it once with your password: open a terminal, run $target and accept. Installing the .deb or .rpm package also solves it." ;;
  esac
  exit 1
fi
exec "$real" "$@"
