// Builds the packages for the system it runs on (Linux, or macOS on a Mac):
//   1. the interface (vite)
//   2. the core, bundled into build/core (JavaScript: the same for every architecture)
//   3. per architecture, the one native module left (node-pty, the terminal), rebuilt for Electron
//      into build/native-<arch>; if it cannot be built, that architecture ships without it and the
//      terminal runs in its fallback mode (it never blocks a release)
//   4. electron-builder: on Linux AppImage (static runtime, no libfuse2), .deb, .rpm and .tar.gz;
//      on macOS a .zip per architecture, signed ad hoc (scripts/after-sign.cjs)
//
//   pnpm --filter @penteos/desktop package                      # this machine's architecture
//   pnpm --filter @penteos/desktop package -- --arch x64,arm64  # several
//   pnpm --filter @penteos/desktop package -- --targets AppImage,deb
//
// Release builds run in scripts/release/ (an old glibc, so the packages run on old distributions).
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { arch as hostArch } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { rebuild } from "@electron/rebuild";

const app = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const root = resolve(app, "..", "..");
const core = join(app, "build", "core");
const run = (cmd, args, cwd = app) => execFileSync(cmd, args, { cwd, stdio: "inherit" });
const flag = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1].split(",").filter(Boolean) : fallback;
};
const host = hostArch() === "arm64" ? "arm64" : "x64";
const arches = flag("arch", [host]);
const mac = process.platform === "darwin";
const targets = flag("targets", mac ? ["zip"] : ["AppImage", "deb", "rpm", "tar.gz"]);
const requireApp = createRequire(join(app, "package.json"));
const electronVersion = requireApp("electron/package.json").version;

console.log("› interface");
run("pnpm", ["exec", "vite", "build"]);

// Paged.js lays out the PDF deliverable; node_modules is not shipped, so it goes with electron/.
mkdirSync(join(app, "electron", "vendor"), { recursive: true });
// The package's exports hide dist/: find its folder from its main entry (lib/index.cjs).
const pagedRoot = dirname(dirname(requireApp.resolve("pagedjs")));
copyFileSync(join(pagedRoot, "dist", "paged.polyfill.js"), join(app, "electron", "vendor", "paged.polyfill.js"));

console.log("› core");
rmSync(core, { recursive: true, force: true });
run("node", [join(root, "scripts/bundle-core.mjs"), core], root);

// A C++ cross compiler for each target architecture (Debian's crossbuild packages).
const CROSS = { arm64: "aarch64-linux-gnu", x64: "x86_64-linux-gnu" };
const built = {};
for (const arch of arches) {
  console.log(`› native module (${arch})`);
  const native = join(app, "build", `native-${arch}`);
  rmSync(native, { recursive: true, force: true });
  mkdirSync(native, { recursive: true });
  copyFileSync(join(core, "package.json"), join(native, "package.json"));
  // Installed without its install script (it would build for this machine), then built for Electron and the target.
  run("npm", ["install", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund", "--no-package-lock"], native);
  // The compiler: the release image's (zig, against an old glibc: PENTEOS_CC_<arch>), else for
  // another architecture Debian's cross compiler, else this machine's.
  const saved = { CC: process.env.CC, CXX: process.env.CXX, LINK: process.env.LINK };
  // On a Mac, Apple's compiler builds for either architecture by itself.
  const cc = process.env[`PENTEOS_CC_${arch}`] ?? (arch !== host && !mac ? `${CROSS[arch]}-gcc` : undefined);
  const cxx = process.env[`PENTEOS_CXX_${arch}`] ?? (arch !== host && !mac ? `${CROSS[arch]}-g++` : undefined);
  if (cc && cxx) {
    process.env.CC = cc;
    process.env.CXX = cxx;
    process.env.LINK = cxx;
  }
  try {
    await rebuild({ buildPath: native, electronVersion, arch, force: true, onlyModules: ["node-pty"] });
    built[arch] = existsSync(join(native, "node_modules", "node-pty", "build", "Release", "pty.node"));
  } catch (e) {
    built[arch] = false;
    console.warn(`  node-pty could not be built for ${arch}: ${e.message}`);
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  if (!built[arch]) {
    // Shipped without it: the terminal runs through `script` (util-linux) instead.
    rmSync(join(native, "node_modules", "node-pty"), { recursive: true, force: true });
    console.warn(`  ${arch}: the terminal will use its fallback mode`);
  }
}
writeFileSync(join(app, "build", "native.json"), JSON.stringify(built, null, 2));

console.log(`› packages (Electron ${electronVersion}; ${arches.join(", ")}; ${targets.join(", ")})`);
run("pnpm", ["exec", "electron-builder", mac ? "--mac" : "--linux", ...targets, ...arches.map((a) => `--${a}`), "--publish", "never"]);
