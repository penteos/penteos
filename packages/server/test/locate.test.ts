import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { cliPath, findCli } from "../src/agents/providers/locate.js";

/** Opened from the desktop menu, the app has a short PATH: installed AI CLIs must still be found. */

let home: string;
const saved = { HOME: process.env.HOME, PATH: process.env.PATH };

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "penteos-home-"));
  process.env.HOME = home;
  process.env.PATH = "/usr/bin:/bin";
});
afterEach(() => {
  process.env.HOME = saved.HOME;
  process.env.PATH = saved.PATH;
  rmSync(home, { recursive: true, force: true });
});

function install(dir: string, name: string) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), "#!/bin/sh\necho ok\n");
  chmodSync(join(dir, name), 0o755);
}

it("finds a CLI in ~/.local/bin and npm's global folder although PATH lacks them", () => {
  install(join(home, ".local", "bin"), "claude");
  install(join(home, ".npm-global", "bin"), "codex");
  expect(findCli("claude")).toBe(join(home, ".local", "bin", "claude"));
  expect(findCli("codex")).toBe(join(home, ".npm-global", "bin", "codex"));
  // The CLI's own children (Codex runs on Node) get the same folders.
  expect(cliPath().split(":")).toEqual(expect.arrayContaining(["/usr/bin", join(home, ".local", "bin"), join(home, ".npm-global", "bin")]));
});

it("says so when it is not installed anywhere", () => {
  expect(findCli("claude-not-installed-here")).toBeUndefined();
});
