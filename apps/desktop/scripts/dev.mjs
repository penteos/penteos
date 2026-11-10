// Starts the Vite dev server and Electron pointed at it.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { createServer } from "vite";

const require = createRequire(import.meta.url);
const server = await createServer({ configFile: new URL("../vite.config.ts", import.meta.url).pathname });
await server.listen();
const url = server.resolvedUrls.local[0];

// Editors built on Electron (VS Code) export ELECTRON_RUN_AS_NODE, which would make Electron
// start as plain Node instead of opening a window.
const env = { ...process.env, VITE_DEV_URL: url, PENTEOS_NODE: process.execPath };
delete env.ELECTRON_RUN_AS_NODE;
// The editor's terminal also says "I am VS Code" (CHROME_DESKTOP, GIO_LAUNCHED_DESKTOP_FILE…):
// Penteos says who it is, or the dock shows a generic icon.
env.CHROME_DESKTOP = "penteos.desktop";
for (const k of ["GIO_LAUNCHED_DESKTOP_FILE", "GIO_LAUNCHED_DESKTOP_FILE_PID", "BAMF_DESKTOP_FILE_HINT", "DESKTOP_STARTUP_ID", "XDG_ACTIVATION_TOKEN"]) delete env[k];
await ensureSandbox(require("electron"));
if (process.argv.includes("--desktop-entry")) await desktopEntry();
const electron = spawn(require("electron"), ["."], { stdio: "inherit", env });
electron.on("exit", async (code) => {
  await server.close();
  process.exit(code ?? 0);
});

/**
 * Ubuntu 24.04+ lets only programs with an AppArmor profile use the user namespaces Chromium's
 * sandbox needs. From VS Code's terminal its profile is inherited; from a plain console this
 * Electron has none, and would abort. Like the packaged launcher (build-resources/launcher.sh): the
 * password once, for a profile that names this exact Electron; never the sandbox turned off.
 */
async function ensureSandbox(electronPath) {
  const { readFileSync, realpathSync, statSync, writeFileSync, mkdtempSync, rmSync, existsSync } = await import("node:fs");
  const { join, dirname } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const { spawnSync } = await import("node:child_process");
  const { createHash } = await import("node:crypto");
  const read = (p) => {
    try {
      return readFileSync(p, "utf8").trim();
    } catch {
      return "";
    }
  };
  if (process.platform !== "linux" || process.getuid?.() === 0) return;
  if (read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") !== "1") return;
  const label = read("/proc/self/attr/current");
  if (label && label !== "unconfined") return;
  try {
    const st = statSync(join(dirname(electronPath), "chrome-sandbox"));
    if (st.uid === 0 && (st.mode & 0o4000) !== 0) return;
  } catch {
    /* no helper */
  }
  const target = realpathSync(electronPath);
  const id = createHash("sha256").update(target).digest("hex").slice(0, 12);
  const dest = `/etc/apparmor.d/penteos-dev-${id}`;
  // Already added (the profile applies to every new start of this Electron).
  if (existsSync(dest)) return;
  if (/["\\*?{}^\[\]\x00-\x1f]/.test(target)) {
    console.error(`penteos (dev): the Electron path (${target}) cannot be used in an AppArmor profile.`);
    process.exit(1);
  }
  console.warn("penteos (dev): this system restricts Chromium's sandbox. Asking for the password once to allow it for this Electron (AppArmor profile); the sandbox stays on.");
  const dir = mkdtempSync(join(tmpdir(), "penteos-aa-"));
  const profile = join(dir, "profile");
  writeFileSync(profile, `abi <abi/4.0>,\ninclude <tunables/global>\n\n# Added by Penteos (development) at the operator's request: lets this Electron use Chromium's sandbox.\nprofile penteos-dev-${id} "${target}" flags=(unconfined) {\n  userns,\n}\n`);
  const r = spawnSync("pkexec", ["/bin/sh", "-c", 'install -m 644 "$1" "$2" && apparmor_parser -r "$2"', "penteos", profile, dest], { stdio: "inherit" });
  rmSync(dir, { recursive: true, force: true });
  if (r.status !== 0) {
    console.error(`penteos (dev): without that permission Chromium cannot sandbox itself and does not open. Alternatively: start it from the VS Code terminal, or, once:\n  sudo chown root:root ${join(dirname(electronPath), "chrome-sandbox")} && sudo chmod 4755 ${join(dirname(electronPath), "chrome-sandbox")}`);
    process.exit(1);
  }
}

/**
 * `pnpm dev -- --desktop-entry`: a menu entry for this development copy, so the dock shows
 * Penteos's icon (GNOME finds an app by its window class and its systemd scope, both "penteos").
 * Opt-in: it writes to the user's applications folder, and never over an installed Penteos.
 */
async function desktopEntry() {
  const { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } = await import("node:fs");
  const { join, dirname, resolve } = await import("node:path");
  const { homedir } = await import("node:os");
  const { execFileSync } = await import("node:child_process");
  if (process.platform !== "linux") return;
  const share = process.env.XDG_DATA_HOME || join(homedir(), ".local", "share");
  const file = join(share, "applications", "penteos.desktop");
  if (["/usr/share/applications/penteos.desktop", "/usr/local/share/applications/penteos.desktop"].some((f) => existsSync(f))) {
    console.warn("penteos (dev): an installed Penteos already has its menu entry; not adding another.");
    return;
  }
  const current = existsSync(file) ? readFileSync(file, "utf8") : "";
  if (current && !current.includes("X-Penteos-Dev=true")) return;
  const app = resolve(dirname(new URL(import.meta.url).pathname), "..");
  const sizes = join(app, "build-resources", "icons");
  for (const f of existsSync(sizes) ? readdirSync(sizes) : []) {
    const m = /^(\d+x\d+)\.png$/.exec(f);
    if (!m) continue;
    const to = join(share, "icons", "hicolor", m[1], "apps", "penteos-dev.png");
    mkdirSync(dirname(to), { recursive: true });
    writeFileSync(to, readFileSync(join(sizes, f)));
  }
  try {
    execFileSync("gtk-update-icon-cache", ["-f", "-t", join(share, "icons", "hicolor")], { stdio: "ignore", timeout: 10_000 });
  } catch {
    /* no cache tool: GTK reads the folder itself */
  }
  const repo = resolve(app, "..", "..");
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(
    file,
    ["[Desktop Entry]", "Name=Penteos (development)", `Exec=pnpm --dir "${repo}" dev`, "Icon=penteos-dev", "Type=Application", "Terminal=false", "Categories=Development;Security;", "StartupWMClass=penteos", "X-Penteos-Dev=true", ""].join("\n"),
    { mode: 0o644 },
  );
  console.log(`penteos (dev): menu entry written to ${file}`);
}
