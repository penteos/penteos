// electron-builder leaves node_modules out of extraResources: copy the core's native module (the
// terminal), already rebuilt for Electron and for this package's architecture, into the app before
// the AppImage, .deb, .rpm and .tar.gz are made. An architecture built without it ships without it
// (the terminal then uses its fallback mode).
const { chmodSync, cpSync, existsSync, readFileSync, renameSync, writeFileSync } = require("node:fs");
const path = require("node:path");

// electron-builder's Arch enum: 0 ia32, 1 x64, 2 armv7l, 3 arm64, 4 universal.
const ARCH = { 1: "x64", 3: "arm64" };

exports.default = async function afterPack(context) {
  const arch = ARCH[context.arch];
  if (!arch) throw new Error(`unsupported architecture ${context.arch}`);
  if (context.electronPlatformName === "linux") rootLauncher(context);
  const from = path.join(__dirname, "..", "build", `native-${arch}`, "node_modules");
  if (!existsSync(from)) return;
  const to = path.join(context.appOutDir, "resources", "core", "node_modules");
  cpSync(from, to, { recursive: true, dereference: true });
};

/**
 * As root, Chromium aborts unless --no-sandbox is on the command line: it checks before main.cjs
 * runs, so the switch cannot come from there. The app's executable becomes a small launcher that
 * adds it only for root (and never when Electron runs as plain Node, which would reject it); the
 * real binary sits next to it. Every way in (menu, /usr/bin, AppImage, tar.gz) goes through it.
 */
function rootLauncher(context) {
  const name = context.packager.executableName;
  const exe = path.join(context.appOutDir, name);
  const real = `${exe}.bin`;
  if (existsSync(real)) return;
  renameSync(exe, real);
  // The launcher's script lives in build-resources/launcher.sh (read it there).
  writeFileSync(exe, readFileSync(path.join(__dirname, "..", "build-resources", "launcher.sh"), "utf8").replaceAll("__NAME__", name));
  chmodSync(exe, 0o755);
}
