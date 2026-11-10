import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/** A plugin folder's files, with the text of the readable ones (for reviewing code before approving it). */
export function pluginFiles(dir: string, maxText = 200 * 1024): Array<{ path: string; bytes: number; text?: string }> {
  const out: Array<{ path: string; bytes: number; text?: string }> = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile()) {
        const bytes = statSync(full).size;
        const path = relative(dir, full).split("\\").join("/");
        let text: string | undefined;
        if (bytes <= maxText) {
          const buf = readFileSync(full);
          if (!buf.includes(0)) text = buf.toString("utf8");
        }
        out.push({ path, bytes, ...(text !== undefined ? { text } : {}) });
      }
      if (out.length >= 300) return;
    }
  };
  walk(dir);
  return out;
}
