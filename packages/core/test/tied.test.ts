import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { reapOrphanListeners, spawnTied } from "../src/index.js";

/**
 * Tools, the interaction listener and the headless browser end with the core, even when the core
 * dies without shutting down. Only `sleep` and short-lived shells are used: nothing reaches a
 * network, and every process here ends on its own within seconds anyway.
 */
const posix = process.platform !== "win32";
const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const waitFor = async (cond: () => boolean, ms = 5000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return cond();
};

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-tied-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe.runIf(posix)("processes tied to the core", () => {
  it("runs the command itself: its output, its exit status and its signals", async () => {
    const ok = spawnTied("sh", ["-c", "echo hola; exit 3"]);
    let out = "";
    ok.stdout?.on("data", (d) => (out += String(d)));
    const [code] = await new Promise<[number | null, NodeJS.Signals | null]>((r) => ok.on("close", (c, s) => r([c, s])));
    expect(out.trim()).toBe("hola");
    expect(code).toBe(3);

    const long = spawnTied("sleep", ["20"]);
    await new Promise((r) => setTimeout(r, 200));
    process.kill(-long.pid!, "SIGINT"); // what cancelling a run does
    const [, signal] = await new Promise<[number | null, NodeJS.Signals | null]>((r) => long.on("close", (c, s) => r([c, s])));
    expect(signal).toBe("SIGINT");
  });

  it("ends when the core dies without shutting down (killed outright)", async () => {
    // A stand-in core: starts a tied sleep, prints its pid, and is then killed with SIGKILL.
    const script = join(dir, "core.mts");
    writeFileSync(script, `import { spawnTied } from ${JSON.stringify(join(import.meta.dirname, "../src/tied.ts"))};\nconst c = spawnTied("sleep", ["20"]);\nconsole.log(c.pid);\nsetInterval(() => {}, 1000);\n`);
    const core = spawn(process.execPath, [script], { stdio: ["ignore", "pipe", "inherit"] });
    const pid = await new Promise<number>((r) => core.stdout!.once("data", (d) => r(Number(String(d).trim()))));
    expect(alive(pid)).toBe(true);
    core.kill("SIGKILL");
    expect(await waitFor(() => !alive(pid))).toBe(true);
  });
});

describe.runIf(process.platform === "linux")("listeners left by a core that died", () => {
  it("stops an orphaned interactsh-client of this workspace's projects, and nothing else", async () => {
    // A stand-in listener: a shell named interactsh-client, with the session file of a project.
    const bin = join(dir, "interactsh-client");
    symlinkSync("/bin/sh", bin);
    const project = join(dir, "project");
    const other = join(dir, "other");
    mkdirSync(join(project, "oob"), { recursive: true });
    const start = (folder: string) => spawnSync("/bin/sh", ["-c", `"${bin}" -c "sleep 8; true" -sf "${join(folder, "oob", "session.yaml")}" >/dev/null 2>&1 & echo $!`], { encoding: "utf8" }).stdout.trim();
    const orphan = Number(start(project)); // its parent shell exits at once: an orphan, like after a crash
    const foreign = Number(start(other)); // another folder: not this workspace's
    expect(await waitFor(() => alive(orphan) && alive(foreign))).toBe(true);

    const reaped = reapOrphanListeners([project]);
    expect(reaped).toEqual([orphan]);
    expect(await waitFor(() => !alive(orphan))).toBe(true);
    expect(alive(foreign)).toBe(true);
    process.kill(foreign, "SIGTERM");
  });
});
