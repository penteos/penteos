import { homedir } from "node:os";
import { join } from "node:path";

/** Where Penteos keeps its data when PENTEOS_DATA_DIR does not say: $XDG_DATA_HOME/penteos (~/.local/share/penteos). */
export function defaultDataDir(): string {
  return join(process.env.XDG_DATA_HOME || join(homedir(), ".local", "share"), "penteos");
}
