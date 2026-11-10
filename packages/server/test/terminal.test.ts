import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { TerminalManager, type TerminalMode } from "../src/terminal.js";

/**
 * The integrated terminal on any Linux: a real pty when
 * node-pty loads, `script` when it does not, a plain shell as the last resort - and the shell never
 * inherits ELECTRON_RUN_AS_NODE (an Electron app opened from it must start as itself).
 */

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-term-"));
  process.env.ELECTRON_RUN_AS_NODE = "1";
});
afterEach(() => {
  delete process.env.ELECTRON_RUN_AS_NODE;
  rmSync(dir, { recursive: true, force: true });
});

function run(mode: TerminalMode): Promise<string> {
  const t = new TerminalManager({ url: "http://127.0.0.1:1", token: "t", workDir: join(dir, "work"), hookDir: join(dir, "hook") }, mode);
  return new Promise((resolve) => {
    let out = "";
    const id = t.open(100, 30, (d) => {
      out += d;
      if (out.includes("PENTEOS-42")) {
        t.closeAll();
        resolve(out);
      }
    }, () => resolve(out));
    setTimeout(() => t.write(id, 'echo "as-node=[${ELECTRON_RUN_AS_NODE:-none}]"; type nmap | head -1; echo PENTEOS-$((40+2))\n'), 300);
    setTimeout(() => {
      t.closeAll();
      resolve(out);
    }, 8000);
  });
}

describe("the integrated terminal", () => {
  // "script" is util-linux's, which only Linux has (macOS ships the BSD one, never used there).
  for (const mode of (process.platform === "linux" ? ["pty", "script", "pipe"] : ["pty", "pipe"]) as Array<"pty" | "script" | "pipe">) {
    it(`works in ${mode} mode, with Penteos's integration and without ELECTRON_RUN_AS_NODE`, async () => {
      const out = await run(mode);
      expect(out).toContain("as-node=[none]");
      expect(out).toMatch(/nmap:? (is a|es una) (function|función)/);
      expect(out).toContain("PENTEOS-42");
    }, 15_000);
  }
});
