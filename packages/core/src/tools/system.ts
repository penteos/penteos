import { execFile, execFileSync } from "node:child_process";
import { accessSync, constants, realpathSync } from "node:fs";
import { delimiter, join } from "node:path";
import type { PackageManager } from "./registry.js";

/**
 * What needs the system: the few things a person must allow with
 * their password, once. Penteos never runs as root for them: it asks the desktop's own password
 * window (pkexec) for one exact command, or shows that command to copy when there is no desktop.
 */

export function which(binary: string, path = process.env.PATH ?? ""): string | undefined {
  for (const dir of path.split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, binary);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      /* next */
    }
  }
  return undefined;
}

/**
 * Whether a password window may be shown: only when the desktop app started this core and said so
 * (PENTEOS_PASSWORD_PROMPTS=1: a person is in front of it), with pkexec and a graphical session.
 * A core on its own, a team server or the test suite never opens one: they show the command.
 */
export function canAskPassword(): boolean {
  return process.env.PENTEOS_PASSWORD_PROMPTS === "1" && Boolean(which("pkexec") && (process.env.DISPLAY || process.env.WAYLAND_DISPLAY));
}

const isRoot = () => typeof process.getuid === "function" && process.getuid() === 0;

/** nmap's packet capture permission, as found: root, the file capability, or none. */
export type CaptureState = "root" | "capability" | "none";

const captureCache = new Map<string, CaptureState>();

/**
 * Whether this nmap may send raw packets (SYN scans, OS detection, UDP). As root it may; otherwise
 * only with the file capability, which nmap needs to be told about (--privileged). Asked to nmap
 * itself with a tiny SYN probe to this machine, so the answer is what nmap will really do (a
 * "nosuid" mount, where the capability has no effect, answers "none" too).
 */
export function captureState(nmap: string): CaptureState {
  if (isRoot()) return "root";
  let real = nmap;
  try {
    real = realpathSync(nmap);
  } catch {
    /* as given */
  }
  const cached = captureCache.get(real);
  if (cached) return cached;
  let state: CaptureState = "none";
  try {
    const out = execFileSync(real, ["--privileged", "-sS", "-p", "1", "-Pn", "-n", "--max-retries", "0", "--host-timeout", "3s", "127.0.0.1"], { timeout: 10_000, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NO_COLOR: "1" } }).toString();
    state = /Nmap done/.test(out) ? "capability" : "none";
  } catch {
    state = "none";
  }
  captureCache.set(real, state);
  return state;
}

export function forgetCaptureState(): void {
  captureCache.clear();
}

/** What nmap cannot do without the capture permission, and what it does instead. */
const RAW_ONLY = new Set(["-O", "--osscan-guess", "--osscan-limit", "--traceroute", "-sU", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX", "-sY", "-sZ", "-sO", "-PE", "-PP", "-PM", "-PO", "-PR"]);

/**
 * Adapts an nmap command to the permission it has: --privileged when the file capability is there;
 * without any, a SYN scan becomes a connect scan, -A keeps versions and scripts, and what only raw
 * packets can do is left out. Says what changed, so the run and the agent know.
 */
export function adaptNmap(argv: string[], state: CaptureState): { argv: string[]; changes: string[] } {
  if (state === "root") return { argv, changes: [] };
  if (state === "capability") return { argv: argv.includes("--privileged") ? argv : ["--privileged", ...argv], changes: [] };
  const out: string[] = [];
  const changes = new Set<string>();
  for (const a of argv) {
    if (a === "--privileged") continue;
    if (a === "-sS") {
      out.push("-sT");
      changes.add("-sS → -sT");
    } else if (a === "-A") {
      out.push("-sV", "-sC");
      changes.add("-A → -sV -sC (no OS detection or traceroute)");
    } else if (RAW_ONLY.has(a)) changes.add(`without ${a}`);
    else out.push(a);
  }
  return { argv: out, changes: [...changes] };
}

export const SETCAP_CAPS = "cap_net_raw,cap_net_admin,cap_net_bind_service+eip";

/** Whether nmap can be given the capture permission once: a file capability exists only on Linux. */
export function captureGrantable(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "linux";
}

/** macOS has no file capabilities: raw packets need root there, and Penteos never scans as root. */
export const MAC_CAPTURE_NOTE = "On macOS raw packets need root, and Penteos never runs a scan as root: nmap scans with connect (-sT), which finds the same open TCP ports; OS detection and UDP are left out.";

/** The command that gives nmap the capture permission (shown, or run through pkexec). */
export function setcapCommand(nmap: string): string[] {
  let real = nmap;
  try {
    real = realpathSync(nmap);
  } catch {
    /* as given */
  }
  return ["setcap", SETCAP_CAPS, real];
}

/** The system package manager's install command, non-interactive (what pkexec runs). */
export function systemInstallArgv(pm: PackageManager, pkg: string): string[] | undefined {
  switch (pm) {
    case "apt":
      return ["apt-get", "install", "-y", pkg];
    case "dnf":
      return ["dnf", "install", "-y", pkg];
    case "zypper":
      return ["zypper", "--non-interactive", "install", pkg];
    case "pacman":
      return ["pacman", "-S", "--needed", "--noconfirm", pkg];
    default:
      return undefined;
  }
}

/**
 * Runs one command with the desktop's password window. Resolves with what happened: done, the
 * person dismissed the window (126/127 from pkexec), or it failed (with its last words).
 */
export function withPassword(argv: string[], timeoutMs = 10 * 60_000): Promise<{ ok: true; output: string } | { ok: false; dismissed: boolean; error: string }> {
  return new Promise((resolve) => {
    execFile("pkexec", argv, { timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (error, stdout, stderr) => {
      const output = `${stdout ?? ""}${stderr ?? ""}`;
      if (!error) return resolve({ ok: true, output });
      const code = (error as { code?: number }).code;
      resolve({ ok: false, dismissed: code === 126 || code === 127, error: output.trim().split("\n").slice(-3).join(" ") || error.message });
    });
  });
}
