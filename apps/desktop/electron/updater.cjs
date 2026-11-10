/**
 * Updates: one question to GitHub (the latest release's VERSION file), never data about the user. When
 * a newer Penteos exists, the app says so and, only when the operator asks, installs it the way it
 * was installed:
 *   - AppImage: the new file is downloaded next to the current one, checked against the release's
 *     SHA256SUMS, swapped in, and the app restarts. No root.
 *   - .deb / .rpm: the package is downloaded and checked the same way, then installed through the
 *     system's own password prompt (pkexec). Never without the operator's click.
 *   - anything else (.tar.gz, a build from source): the release page opens.
 * Off in development, with PENTEOS_NO_UPDATE_CHECK=1, or when the operator turns checks off.
 */
const { app, shell } = require("electron");
const { execFile } = require("node:child_process");
const { createHash } = require("node:crypto");
const { chmodSync, existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");

const REPO = "penteos/penteos";
const DOWNLOAD = `https://github.com/${REPO}/releases/latest/download`;
const EVERY = 6 * 60 * 60 * 1000;

const prefsFile = () => path.join(app.getPath("userData"), "updates.json");
function prefs() {
  try {
    return JSON.parse(readFileSync(prefsFile(), "utf8"));
  } catch {
    return { automatic: true };
  }
}
function savePrefs(p) {
  writeFileSync(prefsFile(), JSON.stringify(p, null, 2));
}

/** "0.1.10" > "0.1.9"; pre-releases (0.2.0-rc.1) never count as newer. */
function newer(latest, current) {
  if (/-/.test(latest)) return false;
  const a = latest.split(".").map(Number);
  const b = current.replace(/-.*/, "").split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0);
  }
  return false;
}

const run = (cmd, args) => new Promise((resolve) => execFile(cmd, args, { timeout: 10_000 }, (error, stdout) => resolve({ ok: !error, out: String(stdout) })));

/** How this copy was installed, and the release file that replaces it. */
async function installKind() {
  const arm = process.arch === "arm64";
  if (process.env.APPIMAGE && existsSync(process.env.APPIMAGE)) return { kind: "appimage", file: `penteos-${arm ? "arm64" : "x86_64"}.AppImage`, target: process.env.APPIMAGE };
  if (process.execPath.startsWith("/opt/Penteos/")) {
    if ((await run("dpkg-query", ["-W", "-f=${Status}", "penteos"])).out.includes("installed")) return { kind: "deb", file: `penteos-${arm ? "arm64" : "amd64"}.deb` };
    if ((await run("rpm", ["-q", "penteos"])).ok) return { kind: "rpm", file: `penteos-${arm ? "aarch64" : "x86_64"}.rpm` };
  }
  return { kind: "manual" };
}

/** The version of the penteos package the system has now ("" if it cannot tell). */
async function installedVersion(kind) {
  const r = kind === "deb" ? await run("dpkg-query", ["-W", "-f=${Version}", "penteos"]) : await run("rpm", ["-q", "--qf", "%{VERSION}", "penteos"]);
  return r.ok ? r.out.trim().replace(/-.*$/, "") : "";
}

/** The lines of a package manager's error that say what went wrong, without crash-reporter noise. */
function packageError(text) {
  const lines = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !/apport|^\s*$/i.test(l));
  const key = lines.filter((l) => /^(E:|dpkg: error|error|Error|Errors were|Se encontraron errores|dpkg: error al)/i.test(l));
  return (key.length ? key : lines).slice(-4).join(" ").slice(0, 400) || "the package manager failed";
}

let state = { status: "idle", current: app.getVersion() };
let listeners = [];
function set(next) {
  state = { ...state, ...next };
  for (const l of listeners) l(state);
}

async function check({ manual = false } = {}) {
  if (!app.isPackaged && !process.env.PENTEOS_UPDATE_DEV) return state;
  if (process.env.PENTEOS_NO_UPDATE_CHECK === "1") return state;
  if (!manual && prefs().automatic === false) return state;
  set({ status: "checking" });
  try {
    // The release's VERSION file, not GitHub's API: plain downloads have no 60-an-hour limit per
    // address, which offices and shared networks would hit. The same file the installer reads.
    const res = await fetch(`${DOWNLOAD}/VERSION`, { headers: { "user-agent": `Penteos/${app.getVersion()}` }, signal: AbortSignal.timeout(8000) });
    if (!res.ok) throw new Error(`GitHub answered ${res.status}`);
    const latest = (await res.text()).trim().replace(/^v/, "");
    if (!/^\d+\.\d+\.\d+$/.test(latest)) throw new Error("the release has no readable VERSION");
    if (!newer(latest, app.getVersion())) {
      set({ status: "current", latest, checkedAt: Date.now() });
      return state;
    }
    const how = await installKind();
    set({ status: "available", latest, url: `https://github.com/${REPO}/releases/tag/v${latest}`, kind: how.kind, checkedAt: Date.now() });
  } catch (e) {
    // Offline or GitHub unreachable: nothing to tell, the next check tries again.
    set({ status: manual ? "error" : "idle", error: e.message });
  }
  return state;
}

/** Downloads to a private folder and refuses anything that does not match SHA256SUMS. */
async function fetchVerified(file) {
  const dir = mkdtempSync(path.join(tmpdir(), "penteos-update-"));
  const sums = await (await fetch(`${DOWNLOAD}/SHA256SUMS`, { signal: AbortSignal.timeout(30_000) })).text();
  const expected = sums.split("\n").map((l) => l.trim().split(/\s+/)).find((p) => p[1] === file)?.[0];
  if (!expected) throw new Error(`${file} is not listed in the release's SHA256SUMS`);
  const res = await fetch(`${DOWNLOAD}/${file}`, { signal: AbortSignal.timeout(15 * 60_000) });
  if (!res.ok || !res.body) throw new Error(`could not download ${file} (${res.status})`);
  const total = Number(res.headers.get("content-length")) || 0;
  const hash = createHash("sha256");
  const chunks = [];
  let got = 0;
  for await (const chunk of res.body) {
    hash.update(chunk);
    chunks.push(chunk);
    got += chunk.length;
    if (total) set({ status: "downloading", progress: Math.round((got / total) * 100) });
  }
  if (hash.digest("hex") !== expected) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error("the download does not match its checksum; nothing was installed");
  }
  const out = path.join(dir, file);
  writeFileSync(out, Buffer.concat(chunks), { mode: 0o600 });
  return { dir, out };
}

/** The operator's "Update": download, verify, install the way this copy was installed. */
async function apply() {
  const how = await installKind();
  if (how.kind === "manual") {
    await shell.openExternal(state.url || `https://github.com/${REPO}/releases/latest`);
    return state;
  }
  set({ status: "downloading", progress: 0, error: undefined });
  let dir;
  try {
    const got = await fetchVerified(how.file);
    dir = got.dir;
    if (how.kind === "appimage") {
      // Next to the running file, then one rename: the old one is replaced whole or not at all.
      const next = `${how.target}.update`;
      writeFileSync(next, readFileSync(got.out), { mode: 0o755 });
      chmodSync(next, 0o755);
      renameSync(next, how.target);
      set({ status: "restarting" });
      app.relaunch({ execPath: how.target, args: process.argv.slice(1) });
      app.exit(0);
      return state;
    }
    set({ status: "installing" });
    const args = how.kind === "deb" ? ["apt-get", "install", "-y", "--allow-downgrades", got.out] : ["sh", "-c", 'if command -v dnf >/dev/null; then dnf install -y "$0"; elif command -v zypper >/dev/null; then zypper -n install --allow-unsigned-rpm "$0"; else yum install -y "$0"; fi', got.out];
    const done = await new Promise((resolve) => execFile("pkexec", args, { timeout: 15 * 60_000 }, (error, _o, stderr) => resolve(error ? { code: error.code, text: String(stderr || error.message) } : undefined)));
    if (done) {
      if (done.code === 126 || done.code === 127 || /dismissed|Not authorized/.test(done.text)) throw new Error("the system password was not given; nothing was installed");
      // apt also tries to finish anything else left half-installed on the system (a kernel whose
      // DKMS module does not build, say) and fails for that even when Penteos went in fine. What
      // counts is the version installed now.
      if ((await installedVersion(how.kind)) !== state.latest) throw new Error(packageError(done.text));
    }
    set({ status: "restarting" });
    app.relaunch();
    app.exit(0);
  } catch (e) {
    set({ status: "error", error: e.message });
  } finally {
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
  return state;
}

function start(onChange) {
  listeners.push(onChange);
  void check();
  setInterval(() => void check(), EVERY).unref();
}

module.exports = {
  start,
  check,
  apply,
  state: () => state,
  automatic: () => prefs().automatic !== false,
  setAutomatic: (on) => savePrefs({ ...prefs(), automatic: Boolean(on) }),
  newer,
};
