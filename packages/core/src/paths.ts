import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Where Penteos keeps its data when PENTEOS_DATA_DIR does not say: $XDG_DATA_HOME/penteos if it is
 * set, otherwise each system's own place: ~/Library/Application Support/Penteos on macOS,
 * ~/.local/share/penteos elsewhere. The desktop app (electron/main.cjs) uses the same rule.
 */
export function defaultDataDir(platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env, home: string = homedir()): string {
  if (env.XDG_DATA_HOME) return join(env.XDG_DATA_HOME, "penteos");
  if (platform === "darwin") return join(home, "Library", "Application Support", "Penteos");
  return join(home, ".local", "share", "penteos");
}
