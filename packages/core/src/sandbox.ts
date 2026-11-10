import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";

/**
 * An offline sandbox for local analysis: a command that declares no targets -
 * a grep over a downloaded bundle, a jq over a tool's output, a Python script on files already in
 * the project - runs with no network at all, so it cannot touch any target and needs no approval.
 * It can read the system, and write only to the project's work folder and /tmp.
 *
 * Linux: bubblewrap when it is there (network and filesystem limits); otherwise a plain network
 * namespace with unshare. macOS: sandbox-exec with a profile that denies the network and every
 * write outside the work folder and the temporary folders (Apple marks the tool deprecated, but it
 * ships with every macOS and is what browsers build on). Without any of them, nothing changes:
 * such commands keep asking a human.
 */

export interface OfflineSandbox {
  kind: "bwrap" | "unshare" | "sandbox-exec";
  /** The command line that runs `command args` offline inside `workDir`. */
  wrap(command: string, args: string[], workDir: string): { command: string; args: string[] };
}

let cached: OfflineSandbox | null | undefined;

const works = (cmd: string, args: string[]) => {
  try {
    return spawnSync(cmd, args, { stdio: "ignore", timeout: 5000 }).status === 0;
  } catch {
    return false;
  }
};

/** The sandbox available on this machine, if any (probed once). */
export function offlineSandbox(): OfflineSandbox | undefined {
  if (cached !== undefined) return cached ?? undefined;
  if (process.env.PENTEOS_NO_SANDBOX === "1" || (process.platform !== "linux" && process.platform !== "darwin")) {
    cached = null;
    return undefined;
  }
  if (process.platform === "darwin") {
    cached = works("/usr/bin/sandbox-exec", ["-p", macProfile("/private/tmp"), "/usr/bin/true"])
      ? { kind: "sandbox-exec", wrap: (command, args, workDir) => ({ command: "/usr/bin/sandbox-exec", args: ["-p", macProfile(workDir), command, ...args] }) }
      : null;
    return cached ?? undefined;
  }
  if (works("bwrap", ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-net", "--die-with-parent", "true"])) {
    cached = {
      kind: "bwrap",
      wrap: (command, args, workDir) => ({
        command: "bwrap",
        args: [
          "--ro-bind", "/", "/",
          "--dev", "/dev",
          "--proc", "/proc",
          "--bind", "/tmp", "/tmp",
          "--bind", workDir, workDir,
          "--unshare-net",
          "--die-with-parent",
          "--chdir", workDir,
          "--", command, ...args,
        ],
      }),
    };
  } else if (works("unshare", ["-rn", "true"])) {
    cached = { kind: "unshare", wrap: (command, args) => ({ command: "unshare", args: ["-rn", "--", command, ...args] }) };
  } else {
    cached = null;
  }
  return cached ?? undefined;
}

/** A quoted path for a sandbox profile (SBPL string syntax). */
const sbplString = (p: string) => `"${p.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

/**
 * The macOS sandbox profile: everything as usual (reading the system, running programs), but no
 * network at all and writes only to the work folder, the temporary folders and the terminal
 * devices. Paths are real paths: the sandbox matches them after links are resolved (/tmp is
 * /private/tmp, the user's temporary folder lives under /private/var/folders).
 */
export function macProfile(workDir: string): string {
  let real = workDir;
  try {
    real = realpathSync(workDir);
  } catch {
    /* not there yet: as given */
  }
  return [
    "(version 1)",
    "(allow default)",
    "(deny network*)",
    "(deny file-write*)",
    `(allow file-write* (subpath ${sbplString(real)}) (subpath "/private/tmp") (subpath "/private/var/folders") (literal "/dev/null") (literal "/dev/zero") (regex #"^/dev/tty") (regex #"^/dev/fd/"))`,
  ].join("\n");
}
