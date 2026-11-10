import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type CodeLimits,
  codeActivator,
  memoryCeiling,
  declarativeActivator,
  executeOperation,
  type OperationContext,
  PluginData,
  PluginHost,
  PluginRuntime,
  PluginSettings,
  pluginTypes,
  Workspace,
} from "../src/index.js";

/**
 * Code plugins: their own logic, in a process of their own. Every limit is
 * tested with tiny ceilings - a refused allocation that never happens, a fraction of a second of
 * CPU, an 800 ms hang - so the tests never weigh on the machine running them.
 */

const human: Actor = { type: "human", id: "01J00000000000000000000000" };
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-code-"));
});
afterEach(() => {
  pluginTypes.clear();
  rmSync(dataDir, { recursive: true, force: true });
});

const CODE = String.raw`
export async function activate(p) {
  p.operation("lookup", async (input, penteos) => {
    const r = await penteos.http({ url: "https://api.lab.test/ip/" + input.ip, headers: { "X-Key": "{{settings.apiKey}}" } });
    const put = await penteos.graph.put("note", { ip: input.ip, text: r.body.text });
    await penteos.store.insert("hits", { ip: input.ip });
    const settings = await penteos.settings();
    return { text: r.body.text, id: put.id, settings, sawSecret: JSON.stringify([r, settings]).includes("TOPSECRET") };
  });
  p.operation("escape", async () => {
    const out = {};
    const attempt = async (name, fn) => { try { await fn(); out[name] = "ESCAPED"; } catch (e) { out[name] = "blocked"; } };
    await attempt("net", () => import("node:net"));
    await attempt("http", () => import("node:http"));
    await attempt("fetch", () => fetch("https://example.com"));
    await attempt("child", () => import("node:child_process"));
    await attempt("worker", () => import("node:worker_threads"));
    await attempt("builtin", () => process.getBuiltinModule("node:dgram"));
    await attempt("binding", () => process.binding("tcp_wrap"));
    await attempt("readHome", async () => (await import("node:fs")).readFileSync(${JSON.stringify(join(homedir(), ".bashrc"))}));
    await attempt("writeTmp", async () => (await import("node:fs")).writeFileSync("/tmp/penteos-plugin-escape", "x"));
    out.env = Object.keys(process.env).sort();
    return out;
  });
  p.operation("crash", async () => { setTimeout(() => process.exit(3), 10); return "bye"; });
  p.operation("hang", async () => { for (;;) {} });
  p.operation("bigalloc", async () => { try { Buffer.alloc(3 * 1024 * 1024 * 1024); return "allocated"; } catch (e) { return "refused"; } });
  p.operation("burn", async () => { setInterval(() => { const t = Date.now(); while (Date.now() - t < 200) {} }, 0); return "returned"; });
  p.operation("flood", async (input, penteos) => { for (let i = 0; i < 300; i++) penteos.log("line " + i); return "sent"; });
  p.operation("annotate", async (input, penteos) => penteos.graph.annotate(input.ip, { x: 1 }));
  p.operation("print", async () => { console.log("hello from the plugin"); process.stdout.write("not a protocol line\n"); return "printed"; });
}
`;

const op = (name: string, extra: Record<string, unknown> = {}) => ({ name, title: name, description: name, handler: name, actors: ["human"], ...extra });

const MANIFEST = {
  id: "lab.coded",
  name: "Coded (lab)",
  version: "1.0.0",
  apiVersion: 1,
  level: "code",
  main: "main.mjs",
  author: { type: "human", name: "Lab" },
  permissions: ["net:api.lab.test", "graph:read", "graph:write"],
  contributes: {
    settings: [{ name: "apiKey", type: "string", secret: true, required: true }, { name: "region", type: "string", default: "eu" }],
    entityTypes: [{ name: "note", label: "Note", fields: [{ name: "ip", type: "string", required: true }, { name: "text", type: "string" }], key: ["ip"] }],
    storage: { project: [{ version: 1, steps: [{ op: "create_table", table: "hits", columns: [{ name: "ip", type: "text", required: true }] }] }] },
    operations: [
      op("lookup", { input: [{ name: "ip", type: "string", required: true }], timeoutMs: 5000 }),
      op("escape", { timeoutMs: 5000 }),
      op("crash"),
      op("hang", { timeoutMs: 1000 }),
      op("bigalloc"),
      op("burn"),
      op("flood"),
      op("print"),
    ],
  },
};

const SMALL: Partial<CodeLimits> = { memoryMb: 256, heapMb: 64, sampleMs: 300, busySamples: 2, idleCpuShare: 0.5, messagesPerWindow: 100, windowMs: 5000 };

async function world(options: { manifest?: Record<string, unknown>; code?: string; kernel?: boolean; approve?: boolean; trust?: "free" | "isolated"; files?: Record<string, string> } = {}) {
  const manifest = options.manifest ?? MANIFEST;
  const dir = join(dataDir, "plugins", String(manifest.id));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "plugin.json"), JSON.stringify(manifest));
  writeFileSync(join(dir, (manifest as { main?: string }).main ?? "main.mjs"), options.code ?? CODE);
  for (const [name, content] of Object.entries(options.files ?? {})) {
    mkdirSync(join(dir, name, ".."), { recursive: true });
    writeFileSync(join(dir, name), content);
  }
  const ws = new Workspace(join(dataDir, "ws"));
  const data = new PluginData({ dataDir, globalVault: () => ws.vault() });
  const settings = new PluginSettings(dataDir, () => ws.vault());
  const requests: Array<{ url: string; headers: Record<string, string> }> = [];
  const fakeFetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    requests.push({ url: String(input), headers: (init.headers ?? {}) as Record<string, string> });
    return new Response(JSON.stringify({ text: `seen ${String(input).split("/").pop()}` }), { headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  const runtime = new PluginRuntime({ data, settings, workspace: ws, fetch: fakeFetch });
  let host: PluginHost;
  const crashes: string[] = [];
  const logs: string[] = [];
  host = new PluginHost({
    dataDir,
    activationBudgetMs: 15_000,
    activators: {
      declarative: declarativeActivator(data, runtime),
      code: codeActivator(data, runtime, {
        hostDir: join(dataDir, "plugin-host"),
        ...(options.kernel !== undefined ? { kernel: options.kernel } : {}),
        limits: SMALL,
        onLog: (_id, t) => logs.push(t),
        onCrash: (id, d) => {
          crashes.push(d);
          host.recordCrash(id, d);
        },
      }),
    },
  });
  runtime.bind(host);
  data.bind(host);
  await host.load();
  host.bootCompleted();
  // These tests are about isolation unless they ask for a free plugin.
  if (options.approve !== false) await host.approve(String(manifest.id), { reviewedCode: true, trust: options.trust ?? "isolated" });
  const eng = ws.create({ clientName: "Lab", name: "Code", mode: "web", plugins: [String(manifest.id)] }, human);
  const ctx = { workspace: ws, caller: { actor: human, policy: { type: "human" } }, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => { throw new Error("no runner"); }, plugins: host, pluginData: data, pluginRuntime: runtime, pluginSettings: settings } as unknown as OperationContext;
  const call = (name: string, input: Record<string, unknown> = {}) => executeOperation(`plugin.${String(manifest.id)}.${name}`, input, ctx);
  await settings.update(String(manifest.id), (manifest.contributes as { settings?: never[] }).settings ?? [], (manifest.contributes as { settings?: unknown[] }).settings ? { apiKey: "TOPSECRET-123" } : {});
  return { ws, host, runtime, eng, call, requests, crashes, logs, close: () => { for (const p of host.list()) runtime.detachCode(p.id)?.stop(); ws.close(); } };
}

describe("approving code", () => {
  it("is refused unless someone says they reviewed it", async () => {
    const w = await world({ approve: false });
    try {
      await expect(w.host.approve("lab.coded")).rejects.toThrow(/after reviewing its code/);
      expect(w.host.get("lab.coded")?.status).toBe("pending");
    } finally {
      w.close();
    }
  });

  it("does not activate if its code does not register what the manifest promises", async () => {
    const w = await world({ code: "export async function activate(p) { p.operation('lookup', async () => 1); }" });
    try {
      expect(w.host.get("lab.coded")).toMatchObject({ status: "disabled", reason: { code: "ACTIVATION_FAILED" } });
      expect(w.host.get("lab.coded")?.reason?.detail).toMatch(/does not register the handlers escape, crash/);
    } finally {
      w.close();
    }
  });
});

describe("folders behind links", () => {
  // On macOS the temporary folder and some homes sit behind links (/var is /private/var); Node's
  // permission model checks real paths, so the plugin must be granted the real ones.
  it("an isolated plugin starts when its folders are reached through a link", async () => {
    const real = dataDir;
    const link = join(mkdtempSync(join(tmpdir(), "penteos-link-")), "data");
    symlinkSync(real, link);
    dataDir = link;
    const w = await world();
    try {
      const r = (await w.call("lookup", { ip: "203.0.113.9" })) as { text: string };
      expect(r.text).toBe("seen 203.0.113.9");
    } finally {
      w.close();
      dataDir = real;
      rmSync(dirname(link), { recursive: true, force: true });
    }
  });
});

describe("what code can do: only through the core", () => {
  it("makes requests, writes the graph and its storage, never sees a secret", async () => {
    const w = await world();
    try {
      const r = (await w.call("lookup", { ip: "203.0.113.9" })) as { text: string; settings: Record<string, unknown>; sawSecret: boolean };
      expect(r.text).toBe("seen 203.0.113.9");
      expect(r.settings).toEqual({ region: "eu" });
      expect(r.sawSecret).toBe(false);
      expect(w.requests[0]).toMatchObject({ url: "https://api.lab.test/ip/203.0.113.9", headers: { "x-key": "TOPSECRET-123" } });
      expect(w.eng.query({ kind: "lab.coded:note" })[0]?.attributes).toMatchObject({ ip: "203.0.113.9", text: "seen 203.0.113.9" });
      expect(w.eng.query({ kind: "lab.coded:note" })[0]?.createdBy).toEqual({ type: "system", id: "plugin:lab.coded" });
      expect(w.eng.auditEvents({ limit: 100 }).some((a) => a.action === "plugin.egress")).toBe(true);
    } finally {
      w.close();
    }
  });

  it("everything else is closed: network, processes, files, the operator's environment", async () => {
    for (const kernel of [false, true]) {
      const w = await world({ kernel });
      try {
        const out = (await w.call("escape")) as Record<string, unknown>;
        const { env, ...tries } = out;
        expect(Object.entries(tries).filter(([, v]) => v !== "blocked"), `kernel=${kernel}`).toEqual([]);
        expect(env).not.toContain("ANTHROPIC_API_KEY");
        expect((env as string[]).every((k) => ["ELECTRON_RUN_AS_NODE", "LANG", "PATH"].includes(k) || k.startsWith("NODE") === false)).toBe(true);
      } finally {
        w.close();
      }
    }
  });

  it("what it prints goes to its log, not into the channel", async () => {
    const w = await world();
    try {
      expect(await w.call("print")).toBe("printed");
      expect(w.logs.join("\n")).toMatch(/hello from the plugin/);
      expect(w.logs.join("\n")).toMatch(/not a protocol line/);
    } finally {
      w.close();
    }
  });
});

describe("misbehaving code: stopped, counted, never the core", () => {
  it("a hang is cut at its time limit and the next call starts a fresh process", async () => {
    const w = await world();
    try {
      const t0 = Date.now();
      await expect(w.call("hang")).rejects.toThrow(/no answer within 1000 ms/);
      expect(Date.now() - t0).toBeLessThan(3000);
      expect(w.host.get("lab.coded")?.health.timeouts).toBe(1);
      expect(await w.call("print")).toBe("printed");
    } finally {
      w.close();
    }
  });

  it("a big allocation is refused by the kernel's ceiling instead of taking the machine's memory", async () => {
    // Only with a ceiling in place: without one the allocation would really happen.
    const ceiling = memoryCeiling(process.execPath, SMALL.memoryMb!);
    if (!ceiling) return;
    const w = await world();
    try {
      expect(await w.call("bigalloc")).toBe("refused");
    } finally {
      w.close();
    }
  });

  it("a process that dies counts as a crash; three and the plugin is off", async () => {
    const w = await world();
    try {
      for (let i = 0; i < 3; i++) {
        await w.call("crash");
        await new Promise((r) => setTimeout(r, 150));
      }
      expect(w.crashes).toHaveLength(3);
      expect(w.host.get("lab.coded")).toMatchObject({ status: "disabled", reason: { code: "TOO_MANY_CRASHES" } });
      await expect(w.call("print")).rejects.toMatchObject({ code: "UNKNOWN_OPERATION" });
    } finally {
      w.close();
    }
  });

  it("burning CPU while nobody calls it ends the process", async () => {
    const w = await world();
    try {
      expect(await w.call("burn")).toBe("returned");
      await new Promise((r) => setTimeout(r, 1500));
      expect(w.crashes.join(" ")).toMatch(/kept the CPU busy/);
    } finally {
      w.close();
    }
  });

  it("flooding the core with messages ends the process", async () => {
    const w = await world();
    try {
      await expect(w.call("flood")).rejects.toThrow(/more than 100 messages/);
      expect(w.crashes.join(" ")).toMatch(/more than 100 messages/);
    } finally {
      w.close();
    }
  });

  it("asking for what it has no permission for is refused by the core", async () => {
    const manifest = { ...MANIFEST, permissions: ["net:api.lab.test", "graph:read"], contributes: { ...MANIFEST.contributes, entityTypes: undefined, operations: [...MANIFEST.contributes.operations, op("annotate", { input: [{ name: "ip", type: "string", required: true }] })] } };
    const w = await world({ manifest });
    try {
      await expect(w.call("lookup", { ip: "203.0.113.9" })).rejects.toThrow(/needs the graph:write permission/);
    } finally {
      w.close();
    }
  });
});

describe("free plugins (the operator's choice): a normal program, watched", () => {
  const FREE_CODE = String.raw`
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import lib from "fake-lib";
export async function activate(p) {
  p.operation("lookup", async (input, penteos) => {
    const out = join(process.env.PENTEOS_PLUGIN_DIR, "out");
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, "note.txt"), "written by a free plugin");
    const echoed = execFileSync("echo", ["from a child process"]).toString().trim();
    const net = await import("node:net");
    return { lib: lib(), echoed, file: readFileSync(join(out, "note.txt"), "utf8"), canNet: typeof net.connect, hasKey: Boolean(process.env.ANTHROPIC_API_KEY) };
  });
  for (const h of ["escape", "crash", "hang", "bigalloc", "burn", "flood", "print"]) p.operation(h, async () => "-");
}
`;

  it("writes files, runs programs, uses its own npm modules and the network modules, without the operator's keys", async () => {
    process.env.ANTHROPIC_API_KEY ??= "sk-test-not-for-plugins";
    const w = await world({ trust: "free", code: FREE_CODE, files: { "node_modules/fake-lib/package.json": JSON.stringify({ name: "fake-lib", type: "module", main: "index.js" }), "node_modules/fake-lib/index.js": "export default () => 'npm module loaded';" } });
    try {
      expect(w.host.get("lab.coded")).toMatchObject({ status: "active", trust: "free" });
      expect(w.runtime.isolationOf("lab.coded")).toBe("free");
      expect(await w.call("lookup", { ip: "x" })).toEqual({ lib: "npm module loaded", echoed: "from a child process", file: "written by a free plugin", canNet: "function", hasKey: false });
    } finally {
      w.close();
    }
  });

  it("can be isolated afterwards, and is then closed again", async () => {
    const w = await world({ trust: "free" });
    try {
      await w.host.setTrust("lab.coded", "isolated");
      expect(w.host.get("lab.coded")).toMatchObject({ status: "active", trust: "isolated" });
      const out = (await w.call("escape")) as Record<string, unknown>;
      const { env: _env, ...tries } = out;
      expect(Object.values(tries).every((v) => v === "blocked")).toBe(true);
    } finally {
      w.close();
    }
  });
});

describe("Python plugins", () => {
  const hasPython = spawnSync("python3", ["--version"]).status === 0;
  const PY = [
    "def activate(plugin):",
    "    @plugin.operation('lookup')",
    "    def lookup(input, penteos):",
    "        import hashlib",
    "        print('python says hello')",
    "        r = penteos.http({'url': 'https://api.lab.test/ip/' + input['ip'], 'headers': {'X-Key': '{{settings.apiKey}}'}})",
    "        put = penteos.graph.put('note', {'ip': input['ip'], 'text': r['body']['text']})",
    "        penteos.store.insert('hits', {'ip': input['ip']})",
    "        return {'text': r['body']['text'], 'md5': hashlib.md5(input['ip'].encode()).hexdigest(), 'id': put['id']}",
    "    for h in ['escape', 'crash', 'hang', 'bigalloc', 'burn', 'flood', 'print']:",
    "        plugin.operation(h, lambda i, p: '-')",
    "",
  ].join("\n");

  it.skipIf(!hasPython)("run free with the same API, through the core for what the core keeps", async () => {
    const manifest = { ...MANIFEST, main: "main.py", runtime: "python" };
    const w = await world({ manifest, code: PY, trust: "free" });
    try {
      expect(w.host.get("lab.coded")?.status).toBe("active");
      const r = (await w.call("lookup", { ip: "203.0.113.5" })) as Record<string, string>;
      expect(r.text).toBe("seen 203.0.113.5");
      expect(r.md5).toHaveLength(32);
      expect(w.requests[0]).toMatchObject({ headers: { "x-key": "TOPSECRET-123" } });
      expect(w.eng.query({ kind: "lab.coded:note" })).toHaveLength(1);
      expect(w.logs.join("\n")).toMatch(/python says hello/);
      await expect(w.host.setTrust("lab.coded", "isolated")).rejects.toThrow(/runs only free/);
    } finally {
      w.close();
    }
  });

  it.skipIf(!hasPython)("running it leaves no bytecode in its folder, so it stays approved; a planted cache does not count", async () => {
    const manifest = { ...MANIFEST, main: "main.py", runtime: "python" };
    const w = await world({ manifest, code: `import helper\n${PY}`, trust: "free", files: { "helper.py": "X = 1\n" } });
    try {
      await w.call("lookup", { ip: "203.0.113.5" });
      const dir = join(dataDir, "plugins", "lab.coded");
      expect(existsSync(join(dir, "__pycache__"))).toBe(false);
      await w.host.rescan();
      expect(w.host.get("lab.coded")?.status).toBe("active");
      // A cache someone else left there is not the plugin: the fingerprint ignores it.
      mkdirSync(join(dir, "__pycache__"));
      writeFileSync(join(dir, "__pycache__", "helper.cpython-312.pyc"), "planted");
      await w.host.rescan();
      expect(w.host.get("lab.coded")?.status).toBe("active");
    } finally {
      w.close();
    }
  });
});
