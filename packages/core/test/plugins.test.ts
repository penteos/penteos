import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { BREAKER, executeOperation, type OperationContext, PluginHost, type PluginActivator, PluginUnavailableError, Workspace } from "../src/index.js";

/**
 * The plugin safety net, tested with plugins that break on purpose.
 * The rule every test checks: whatever a plugin does, the host keeps going, the plugin ends up off
 * with the right reason, and the operator is told.
 */

const here = dirname(fileURLToPath(import.meta.url));
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-plugins-"));
});
afterEach(() => {
  rmSync(dataDir, { recursive: true, force: true });
});

const manifest = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  name: `Plugin ${id}`,
  version: "1.0.0",
  apiVersion: 1,
  level: "declarative",
  author: { type: "human", name: "Lab" },
  permissions: ["graph:read"],
  ...extra,
});

/** Writes a plugin folder; `body` may be any text (to break the JSON on purpose). */
function plugin(folder: string, body: unknown, files: Record<string, string> = {}): string {
  const dir = join(dataDir, "plugins", folder);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "plugin.json"), typeof body === "string" ? body : JSON.stringify(body));
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
  return dir;
}

const ok: PluginActivator = { activate: () => undefined };
const host = (activators: Record<string, PluginActivator> = { declarative: ok }, extra: Partial<ConstructorParameters<typeof PluginHost>[0]> = {}) =>
  new PluginHost({ dataDir, activators, activationBudgetMs: 60, ...extra });

/** A host that loads, approves every pending plugin and completes its start. */
async function installed(ids: string[], activators?: Record<string, PluginActivator>) {
  const h = host(activators);
  await h.load();
  for (const id of ids) await h.approve(id);
  h.bootCompleted();
  return h;
}

describe("loading", () => {
  it("an empty folder starts fine", async () => {
    const h = host();
    expect(await h.load()).toEqual([]);
  });

  it("a plugin is not trusted on sight: it waits for approval, then runs on every start", async () => {
    let calls = 0;
    plugin("good", manifest("lab.good"));
    const h = host({ declarative: { activate: () => void calls++ } });
    await h.load();
    expect(h.get("lab.good")?.status).toBe("pending");
    expect(h.get("lab.good")?.reason?.code).toBe("NOT_APPROVED");
    expect(calls).toBe(0);
    await h.approve("lab.good");
    expect(h.get("lab.good")?.status).toBe("active");
    h.bootCompleted();
    const next = host({ declarative: { activate: () => void calls++ } });
    await next.load();
    expect(next.get("lab.good")?.status).toBe("active");
    expect(calls).toBe(2);
  });

  it("broken neighbours never stop a good plugin, and each one says why", async () => {
    plugin("a-json", "{ not json");
    mkdirSync(join(dataDir, "plugins", "b-empty"), { recursive: true });
    plugin("c-schema", manifest("NOT VALID"));
    plugin("d-api", manifest("lab.api", { apiVersion: 99 }));
    plugin("e-engine", manifest("lab.engine", { engine: ">=99.0.0" }));
    plugin("f-extra", manifest("lab.extra", { surprise: true }));
    plugin("g-code", manifest("lab.code", { level: "code" }));
    const linked = plugin("h-link", manifest("lab.link"));
    symlinkSync("/etc/hostname", join(linked, "escape"));
    plugin("i-dup1", manifest("lab.dup"));
    plugin("j-dup2", manifest("lab.dup"));
    plugin("z-good", manifest("lab.good"));
    const h = await installed(["lab.good"]);
    const byFolder = Object.fromEntries(h.list().map((p) => [p.folder, p]));
    expect(byFolder["a-json"]).toMatchObject({ status: "invalid", reason: { code: "INVALID_JSON" } });
    expect(byFolder["b-empty"]).toMatchObject({ status: "invalid", reason: { code: "INVALID_MANIFEST" } });
    expect(byFolder["c-schema"]?.reason?.detail).toMatch(/^id:/);
    expect(byFolder["d-api"]).toMatchObject({ status: "incompatible", reason: { code: "INCOMPATIBLE_API" } });
    expect(byFolder["e-engine"]).toMatchObject({ status: "incompatible", reason: { code: "INCOMPATIBLE_ENGINE" } });
    expect(byFolder["f-extra"]).toMatchObject({ status: "invalid", reason: { code: "INVALID_MANIFEST" } });
    expect(byFolder["g-code"]?.reason?.detail).toMatch(/main/);
    expect(byFolder["h-link"]).toMatchObject({ status: "invalid", reason: { code: "INVALID_PACKAGE" } });
    expect(byFolder["j-dup2"]).toMatchObject({ status: "invalid", reason: { code: "DUPLICATE_ID" } });
    expect(byFolder["z-good"]?.status).toBe("active");
  });

  it("a level this version cannot run is incompatible, not a crash", async () => {
    plugin("code", manifest("lab.code", { level: "code", main: "index.js" }), { "index.js": "export {}" });
    const h = host({ declarative: ok });
    await h.load();
    await h.approve("lab.code", { reviewedCode: true });
    expect(h.get("lab.code")).toMatchObject({ status: "incompatible", reason: { code: "LEVEL_UNAVAILABLE" } });
  });

  it("reports progress plugin by plugin, ending at the total", async () => {
    plugin("a", manifest("lab.a"));
    plugin("b", manifest("lab.b"));
    await installed(["lab.a", "lab.b"]);
    const seen: Array<{ done: number; total: number }> = [];
    await host().load((p) => seen.push({ done: p.done, total: p.total }));
    expect(seen.at(-1)).toEqual({ done: 2, total: 2 });
  });
});

describe("tampering", () => {
  it("a plugin whose files changed stops until approved again, and says so once", async () => {
    const dir = plugin("p", manifest("lab.p"), { "data.json": "{}" });
    await installed(["lab.p"]);
    writeFileSync(join(dir, "data.json"), '{"changed": true}');
    const h = host();
    await h.load();
    expect(h.get("lab.p")).toMatchObject({ status: "modified", reason: { code: "MODIFIED" } });
    expect(h.notices().items.map((n) => n.code)).toEqual(["MODIFIED"]);
    h.dismissNotices();
    h.bootCompleted();
    const again = host();
    await again.load();
    expect(again.notices().items).toEqual([]); // no repeat at every start
    await expect(again.enable("lab.p")).rejects.toThrow(/approve it again/);
    await again.approve("lab.p");
    expect(again.get("lab.p")?.status).toBe("active");
  });
});

describe("activation", () => {
  it("one that throws is disabled with the reason and the others still run", async () => {
    plugin("bad", manifest("lab.bad"));
    plugin("good", manifest("lab.good"));
    const activators = {
      declarative: {
        activate: (p: { id: string }) => {
          if (p.id === "lab.bad") throw new Error("boom at activation");
        },
      },
    };
    const h = await installed(["lab.bad", "lab.good"], activators);
    expect(h.get("lab.bad")).toMatchObject({ status: "disabled", reason: { code: "ACTIVATION_FAILED", auto: true } });
    expect(h.get("lab.bad")?.reason?.detail).toContain("boom");
    expect(h.get("lab.good")?.status).toBe("active");
    expect(h.notices().items).toMatchObject([{ id: "lab.bad", code: "ACTIVATION_FAILED" }]);
    expect(h.logOf("lab.bad").join("\n")).toContain("ACTIVATION_FAILED");
  });

  it("one that hangs does not hold the start: it is marked slow and becomes active when it finishes", async () => {
    plugin("slow", manifest("lab.slow"));
    plugin("fast", manifest("lab.fast"));
    let release!: () => void;
    const activators = {
      declarative: {
        activate: (p: { id: string }) => (p.id === "lab.slow" ? new Promise<void>((r) => (release = r)) : undefined),
      },
    };
    await installed([], activators);
    const first = host(activators);
    await first.load();
    await first.approve("lab.fast");
    const started = Date.now();
    await first.approve("lab.slow");
    expect(Date.now() - started).toBeLessThan(1000);
    expect(first.get("lab.slow")).toMatchObject({ status: "slow", reason: { code: "ACTIVATION_TIMEOUT" } });
    expect(first.get("lab.fast")?.status).toBe("active");
    release();
    await new Promise((r) => setTimeout(r, 10));
    expect(first.get("lab.slow")?.status).toBe("active");
  });

  it("one that hangs and then fails ends disabled", async () => {
    plugin("p", manifest("lab.p"));
    let fail!: (e: Error) => void;
    const h = host({ declarative: { activate: () => new Promise<void>((_r, j) => (fail = j)) } });
    await h.load();
    await h.approve("lab.p");
    expect(h.get("lab.p")?.status).toBe("slow");
    fail(new Error("gave up"));
    await new Promise((r) => setTimeout(r, 10));
    expect(h.get("lab.p")).toMatchObject({ status: "disabled", reason: { code: "ACTIVATION_FAILED" } });
  });

  it("the crash marker is on disk exactly while a plugin activates", async () => {
    plugin("p", manifest("lab.p"));
    const marker = join(dataDir, "plugin-host", "activating.json");
    let during = false;
    const h = host({ declarative: { activate: () => void (during = existsSync(marker)) } });
    await h.load();
    await h.approve("lab.p");
    expect(during).toBe(true);
    expect(existsSync(marker)).toBe(false);
  });

  it("a real crash while activating: the next start blames that plugin and disables it", async () => {
    plugin("a-crashes", manifest("lab.crashes"));
    plugin("b-good", manifest("lab.good"));
    await installed(["lab.crashes", "lab.good"]);
    // A start that dies (exit 70) while activating the first plugin, "a-crashes".
    // tsx is a dependency of the server package: run from there so `--import tsx` resolves.
    const crashed = spawnSync(process.execPath, ["--import", "tsx", join(here, "fixtures", "crash-on-activate.ts"), dataDir], { encoding: "utf8", timeout: 30_000, cwd: join(here, "..", "..", "server") });
    expect(crashed.status, crashed.stderr).toBe(70);
    expect(existsSync(join(dataDir, "plugin-host", "activating.json"))).toBe(true);
    const next = host();
    await next.load();
    expect(next.get("lab.crashes")).toMatchObject({ status: "disabled", reason: { code: "CRASH_ON_ACTIVATE", auto: true } });
    expect(next.get("lab.good")?.status).toBe("active");
    expect(next.notices().items).toMatchObject([{ id: "lab.crashes", code: "CRASH_ON_ACTIVATE" }]);
    expect(existsSync(join(dataDir, "plugin-host", "activating.json"))).toBe(false);
  }, 40_000);
});

describe("safe mode", () => {
  it("two starts that never complete put the next one in safe mode; a good start clears it", async () => {
    plugin("p", manifest("lab.p"));
    await installed(["lab.p"]);
    let calls = 0;
    const counting = { declarative: { activate: () => void calls++ } };
    await host(counting).load(); // never completes
    await host(counting).load(); // never completes
    calls = 0;
    const third = host(counting);
    await third.load();
    expect(third.safeMode).toBe(true);
    expect(third.notices()).toMatchObject({ safeMode: true, autoSafeMode: true });
    expect(third.get("lab.p")).toMatchObject({ status: "safe_mode", reason: { code: "SAFE_MODE" } });
    expect(calls).toBe(0);
    third.bootCompleted();
    const fourth = host(counting);
    await fourth.load();
    expect(fourth.safeMode).toBe(false);
    expect(fourth.get("lab.p")?.status).toBe("active");
  });

  it("asked for explicitly, nothing activates", async () => {
    plugin("p", manifest("lab.p"));
    await installed(["lab.p"]);
    let calls = 0;
    const h = host({ declarative: { activate: () => void calls++ } }, { safeMode: true });
    await h.load();
    expect(h.get("lab.p")?.status).toBe("safe_mode");
    expect(calls).toBe(0);
  });
});

describe("the breaker at run time", () => {
  it(`${BREAKER.errors} errors in the window disable the plugin; old errors do not count`, async () => {
    plugin("p", manifest("lab.p"));
    let now = Date.parse("2026-11-06T10:00:00Z");
    const h = host({ declarative: ok }, { now: () => now });
    await h.load();
    await h.approve("lab.p");
    const fail = () => h.guard("lab.p", () => Promise.reject(new Error("upstream said no")));
    for (let i = 0; i < BREAKER.errors - 1; i++) await expect(fail()).rejects.toThrow("upstream said no");
    now += BREAKER.windowMs + 1000; // the earlier ones age out
    for (let i = 0; i < BREAKER.errors - 1; i++) await expect(fail()).rejects.toThrow("upstream said no");
    expect(h.get("lab.p")?.status).toBe("active");
    await expect(fail()).rejects.toThrow();
    await new Promise((r) => setTimeout(r, 5));
    expect(h.get("lab.p")).toMatchObject({ status: "disabled", reason: { code: "TOO_MANY_ERRORS", auto: true } });
    await expect(h.guard("lab.p", () => 1)).rejects.toBeInstanceOf(PluginUnavailableError);
    expect(h.notices().items).toMatchObject([{ id: "lab.p", code: "TOO_MANY_ERRORS" }]);
  });

  it("calls that never answer count as timeouts", async () => {
    plugin("p", manifest("lab.p"));
    const h = host();
    await h.load();
    await h.approve("lab.p");
    for (let i = 0; i < BREAKER.timeouts; i++) await expect(h.guard("lab.p", () => new Promise(() => undefined), 10)).rejects.toThrow(/no answer/);
    await new Promise((r) => setTimeout(r, 5));
    expect(h.get("lab.p")?.reason?.code).toBe("TOO_MANY_TIMEOUTS");
  });

  it("reported crashes (a dead plugin process, a panel that exploded) trip it too", async () => {
    plugin("p", manifest("lab.p"));
    const h = host();
    await h.load();
    await h.approve("lab.p");
    for (let i = 0; i < BREAKER.crashes; i++) h.recordCrash("lab.p", "process exited");
    await new Promise((r) => setTimeout(r, 5));
    expect(h.get("lab.p")?.reason?.code).toBe("TOO_MANY_CRASHES");
  });

  it("a successful call returns the plugin's value and counts nothing", async () => {
    plugin("p", manifest("lab.p"));
    const h = host();
    await h.load();
    await h.approve("lab.p");
    expect(await h.guard("lab.p", () => 42)).toBe(42);
    expect(h.get("lab.p")?.health).toEqual({ errors: 0, timeouts: 0, crashes: 0 });
  });
});

describe("the operator's switches", () => {
  it("disabling is quiet and keeps the plugin; enabling starts its history over", async () => {
    plugin("p", manifest("lab.p"));
    let off = 0;
    const h = host({ declarative: { activate: () => undefined, deactivate: () => void off++ } });
    await h.load();
    await h.approve("lab.p");
    await h.disable("lab.p");
    expect(h.get("lab.p")).toMatchObject({ status: "disabled", reason: { code: "DISABLED_BY_USER", auto: false } });
    expect(off).toBe(1);
    expect(h.notices().items).toEqual([]);
    h.recordCrash("lab.p", "x");
    await h.enable("lab.p");
    expect(h.get("lab.p")).toMatchObject({ status: "active", health: { errors: 0, timeouts: 0, crashes: 0 } });
  });

  it("a deactivate that throws does not stop the plugin from going off", async () => {
    plugin("p", manifest("lab.p"));
    const h = host({ declarative: { activate: () => undefined, deactivate: () => { throw new Error("cannot stop"); } } });
    await h.load();
    await h.approve("lab.p");
    await h.disable("lab.p");
    expect(h.get("lab.p")?.status).toBe("disabled");
  });

  it("an unreadable state starts over safely: every plugin needs approval again", async () => {
    plugin("p", manifest("lab.p"));
    await installed(["lab.p"]);
    writeFileSync(join(dataDir, "plugin-host", "state.json"), "{ broken");
    const h = host();
    await h.load();
    expect(h.notices().stateReset).toBe(true);
    expect(h.get("lab.p")?.status).toBe("pending");
    expect(readdirSync(join(dataDir, "plugin-host")).some((f) => f.startsWith("state.json.corrupt-"))).toBe(true);
  });
});

describe("operations", () => {
  const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
  const agent: Actor = { type: "agent", id: "01JA00000000000000000000A1" };

  it("humans list, approve and switch plugins; agents cannot; a core without plugins says so", async () => {
    plugin("p", manifest("lab.p"));
    const ws = new Workspace(join(dataDir, "ws"));
    const h = host();
    await h.load();
    const ctx = (actor: Actor, plugins: PluginHost | null = h) =>
      ({ workspace: ws, caller: { actor, policy: { type: actor.type, autonomy: "autonomous", maxRisk: "active" } }, engagement: () => { throw new Error("none"); }, runner: () => { throw new Error("none"); }, ...(plugins ? { plugins } : {}) }) as unknown as OperationContext;
    try {
      const listed = (await executeOperation("plugin.list", {}, ctx(human))) as { plugins: Array<{ id: string; status: string }> };
      expect(listed.plugins).toMatchObject([{ id: "lab.p", status: "pending" }]);
      await expect(executeOperation("plugin.approve", { id: "lab.p" }, ctx(agent))).rejects.toBeTruthy();
      expect(await executeOperation("plugin.approve", { id: "lab.p" }, ctx(human))).toMatchObject({ status: "active" });
      expect(await executeOperation("plugin.disable", { id: "lab.p" }, ctx(human))).toMatchObject({ status: "disabled" });
      await expect(executeOperation("plugin.enable", { id: "lab.nope" }, ctx(human))).rejects.toMatchObject({ code: "CONFLICT" });
      await expect(executeOperation("plugin.list", {}, ctx(human, null))).rejects.toMatchObject({ code: "PLUGIN_UNAVAILABLE" });
    } finally {
      ws.close();
    }
  });
});
