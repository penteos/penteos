import { accessSync, constants, existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";

/**
 * Where the AI command-line tools live. A desktop app opened from the menu does not get the PATH a
 * terminal has (~/.local/bin, npm's global folder and nvm are added by shell start-up files), so
 * an installed and signed-in Claude Code or Codex would look missing. These are the folders their
 * official installers and the usual Node setups put them in.
 */
function extraDirs(): string[] {
  const home = homedir();
  const dirs = [
    join(home, ".local", "bin"),
    join(home, ".claude", "local"),
    join(home, ".npm-global", "bin"),
    join(home, ".bun", "bin"),
    join(home, ".volta", "bin"),
    join(home, ".yarn", "bin"),
    join(home, ".deno", "bin"),
    join(home, "n", "bin"),
    "/usr/local/bin",
    "/opt/homebrew/bin",
  ];
  // nvm: every installed Node, newest first.
  const nvm = join(home, ".nvm", "versions", "node");
  if (existsSync(nvm)) {
    try {
      for (const v of readdirSync(nvm).sort().reverse()) dirs.push(join(nvm, v, "bin"));
    } catch {
      /* unreadable: skip */
    }
  }
  return dirs;
}

/** PATH plus the usual install folders, without duplicates (also what the CLI itself needs: Codex runs on Node). */
export function cliPath(): string {
  const seen = new Set<string>();
  return [...(process.env.PATH ?? "").split(delimiter), ...extraDirs()].filter((d) => d && existsSync(d) && !seen.has(d) && seen.add(d)).join(delimiter);
}

/** The full path of an installed command, or undefined. */
export function findCli(name: string): string | undefined {
  for (const dir of cliPath().split(delimiter)) {
    const file = join(dir, name);
    try {
      accessSync(file, constants.X_OK);
      return file;
    } catch {
      /* not here */
    }
  }
  return undefined;
}
