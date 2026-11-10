/**
 * The PATH the operator's tools live on. An app opened from the Dock (macOS) or some launchers
 * (Linux) gets a bare PATH: /usr/bin:/bin:/usr/sbin:/sbin, without Homebrew or ~/go/bin, so nmap,
 * nuclei or the Claude Code CLI installed there would look missing. This asks the operator's own
 * login shell for its PATH once, at start (bounded in time: a slow or interactive shell profile
 * never holds the app), and adds the usual tool folders that exist. The core and the terminals
 * inherit it.
 */
const { execFile } = require("node:child_process");
const { existsSync } = require("node:fs");
const { homedir } = require("node:os");
const path = require("node:path");

const MARK = "__PENTEOS_PATH__";

/** Folders where tools commonly live, in the order they should win after the shell's own PATH. */
function knownDirs(home = homedir()) {
  return [
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    path.join(home, "go", "bin"),
    path.join(home, ".local", "bin"),
    path.join(home, ".cargo", "bin"),
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
  ];
}

/** The shell's PATH first, then the one the app got, then the known folders that exist; no repeats. */
function mergePath(fromShell, current, exists = existsSync, home = homedir()) {
  const out = [];
  for (const dir of [...(fromShell || "").split(":"), ...(current || "").split(":"), ...knownDirs(home).filter((d) => exists(d))]) {
    if (dir && path.isAbsolute(dir) && !out.includes(dir)) out.push(dir);
  }
  return out.join(":");
}

/** The PATH the login shell prints between markers (profiles may print other things around it). */
function parseShellOutput(text) {
  const m = new RegExp(`${MARK}(.*?)${MARK}`, "s").exec(text || "");
  return m ? m[1].trim() : "";
}

function shellPath(timeoutMs = 3000) {
  return new Promise((resolve) => {
    const shell = process.env.SHELL && existsSync(process.env.SHELL) ? process.env.SHELL : process.platform === "darwin" ? "/bin/zsh" : "/bin/sh";
    try {
      execFile(
        shell,
        ["-ilc", `printf '%s%s%s' '${MARK}' "$PATH" '${MARK}'`],
        // oh-my-zsh and similar can stop to ask about updates: never here.
        { timeout: timeoutMs, env: { ...process.env, DISABLE_AUTO_UPDATE: "true", ZSH_DISABLE_COMPFIX: "true", PENTEOS_SHELL_PATH: "1" }, stdio: ["ignore", "pipe", "ignore"] },
        (_error, stdout) => resolve(parseShellOutput(String(stdout || ""))),
      );
    } catch {
      resolve("");
    }
  });
}

/** Sets process.env.PATH to the operator's full PATH (not on Windows). Never throws, never waits long. */
async function adoptShellPath() {
  if (process.platform === "win32") return process.env.PATH;
  const fromShell = await shellPath();
  process.env.PATH = mergePath(fromShell, process.env.PATH);
  return process.env.PATH;
}

module.exports = { adoptShellPath, mergePath, parseShellOutput, knownDirs };
