import { type ChildProcess, spawn, type SpawnOptions } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";

/**
 * Processes that end with the core. Tools, the interaction listener and the agents' headless
 * browser run in their own process group (so stopping one stops what it launched), which also
 * means nothing ends them if the core dies without its shutdown: a crash, a forced quit, an
 * update. A scan would keep going against the target with nobody able to stop it.
 *
 * On Linux and macOS the command starts under a small sh watchdog that holds a pipe to the core
 * and then becomes the command itself (exec: same pid, same signals, same exit status). A
 * background reader waits on the pipe; when the core goes, the pipe closes and the whole group
 * gets SIGTERM, then SIGKILL three seconds later. The reader holds none of the command's output,
 * so the core sees it close when the command ends. When the command ends normally the core closes
 * the pipe, so the reader cleans up whatever the command left behind and exits.
 */
const WATCHDOG =
  'exec 3<&0; (trap "" TERM INT; cat <&3 >/dev/null; kill -TERM -$$ 2>/dev/null; sleep 3; kill -KILL -$$ 2>/dev/null) </dev/null >/dev/null 2>&1 & exec "$0" "$@" </dev/null 3<&-';

export type TiedOptions = Omit<SpawnOptions, "stdio" | "detached"> & {
  /** What happens to the command's output: piped to the core or discarded. */
  output?: "pipe" | "ignore";
};

export function spawnTied(command: string, args: string[], options: TiedOptions = {}): ChildProcess {
  const { output = "pipe", ...rest } = options;
  if (process.platform === "win32") return spawn(command, args, { ...rest, stdio: ["ignore", output, output] });
  const child = spawn("/bin/sh", ["-c", WATCHDOG, command, ...args], { ...rest, stdio: ["pipe", output, output], detached: true });
  child.stdin?.on("error", () => undefined);
  child.once("exit", () => child.stdin?.end());
  return child;
}

/**
 * Interaction listeners left by a core that died before this fix (or killed outright): any
 * interactsh-client using the session file of one of these engagement folders, not started by
 * this process, is stopped. Linux only (it reads /proc); elsewhere it does nothing.
 */
export function reapOrphanListeners(engagementDirs: string[]): number[] {
  if (process.platform !== "linux" || !engagementDirs.length) return [];
  const sessions = new Set(engagementDirs.map((d) => `${d.replace(/\/+$/, "")}/oob/session.yaml`));
  const reaped: number[] = [];
  let pids: string[];
  try {
    pids = readdirSync("/proc").filter((p) => /^\d+$/.test(p));
  } catch {
    return [];
  }
  for (const p of pids) {
    const pid = Number(p);
    if (pid === process.pid) continue;
    try {
      const argv = readFileSync(`/proc/${p}/cmdline`, "utf8").split("\0");
      if (!argv[0]?.endsWith("interactsh-client")) continue;
      const sf = argv[argv.indexOf("-sf") + 1];
      if (!sf || !sessions.has(sf)) continue;
      const ppid = Number(/^PPid:\s+(\d+)/m.exec(readFileSync(`/proc/${p}/status`, "utf8"))?.[1]);
      if (ppid === process.pid) continue;
      process.kill(pid, "SIGTERM");
      reaped.push(pid);
    } catch {
      /* gone meanwhile, or not ours to read */
    }
  }
  return reaped;
}
