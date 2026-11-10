import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  codeActivator,
  declarativeActivator,
  executeOperation,
  offlineSandbox,
  type OperationContext,
  outputDir,
  PluginData,
  PluginDrafts,
  PluginHost,
  PluginRuntime,
  PluginSettings,
  pluginTypes,
  ToolRegistry,
  ToolRunner,
  Workspace,
} from "../src/index.js";

/**
 * The Maestro writes code plugins: drafts with files, tested
 * isolated in the sandbox, proposed with their code and what changed, installed only once a person
 * says they reviewed it - isolated unless that person frees it.
 */

const human: Actor = { type: "human", id: "01J00000000000000000000000" };
const maestro: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-builder-code-"));
});
afterEach(() => {
  pluginTypes.clear();
  rmSync(dataDir, { recursive: true, force: true });
});

async function world() {
  const ws = new Workspace(join(dataDir, "ws"));
  const data = new PluginData({ dataDir, globalVault: () => ws.vault() });
  const settings = new PluginSettings(dataDir, () => ws.vault());
  const runtime = new PluginRuntime({ data, settings, workspace: ws });
  const host = new PluginHost({
    dataDir,
    activators: { declarative: declarativeActivator(data, runtime), code: codeActivator(data, runtime, { hostDir: join(dataDir, "plugin-host"), limits: { sampleMs: 300 } }) },
    activationBudgetMs: 15_000,
  });
  runtime.bind(host);
  data.bind(host);
  await host.load();
  host.bootCompleted();
  const drafts = new PluginDrafts(dataDir, host);
  const eng = ws.create({ clientName: "ACME", name: "Recon", mode: "web" }, human);
  let runner: ToolRunner | undefined;
  const runnerFor = () => {
    if (!runner) {
      runner = new ToolRunner(eng, new ToolRegistry(join(dataDir, "tools")));
      runner.pluginInstall = (proposal, by, options) => drafts.install(proposal, eng, by, options);
    }
    return runner;
  };
  const ctx = (actor: Actor): OperationContext =>
    ({
      workspace: ws,
      caller: { actor, policy: { type: actor.type === "agent" ? "agent" : "human", autonomy: "autonomous", maxRisk: "active" } },
      defaultEngagementId: eng.info.id,
      engagement: () => eng,
      runner: () => runnerFor(),
      plugins: host,
      pluginData: data,
      pluginRuntime: runtime,
      pluginSettings: settings,
      pluginDrafts: drafts,
    }) as unknown as OperationContext;
  const as = (actor: Actor) => (op: string, input: Record<string, unknown> = {}) => executeOperation(op, input, ctx(actor));
  return { ws, host, drafts, eng, runtime, maestro: as(maestro), human: as(human), close: () => { for (const p of host.list()) runtime.detachCode(p.id)?.stop(); ws.close(); } };
}

const MANIFEST = {
  id: "maestro.hosts-csv",
  name: "Hosts to CSV",
  version: "0.1.0",
  level: "code",
  main: "main.mjs",
  permissions: ["graph:read", "files:write"],
  contributes: {
    operations: [{ name: "export", title: "Export hosts", action: "Export CSV", description: "Writes the project's hosts as a CSV", handler: "export", input: [{ name: "sep", type: "string", default: "," }] }],
  },
};

const CODE_V1 = `import { toRow } from "./lib/csv.mjs";
export async function activate(plugin) {
  plugin.operation("export", async (input, penteos) => {
    const hosts = await penteos.graph.query("host");
    const lines = ["ip", ...hosts.map((h) => toRow([h.attributes.ip], input.sep))];
    const file = await penteos.files.write("hosts.csv", lines.join("\\n"));
    return { hosts: hosts.length, file: file.name };
  });
}
`;
const LIB = `export const toRow = (cells, sep) => cells.map((c) => String(c ?? "")).join(sep || ",");\n`;

describe("a code draft", () => {
  it("holds its files, checks them, and its fingerprint covers every one", async () => {
    const w = await world();
    try {
      const v = (await w.maestro("plugin.draft_write", { manifest: MANIFEST, files: { "main.mjs": CODE_V1, "lib/csv.mjs": LIB } })) as { id: string; level: string; valid: boolean; files: Array<{ path: string }>; hash: string };
      expect(v).toMatchObject({ id: "maestro.hosts-csv", level: "code", valid: true });
      expect(v.files.map((f) => f.path)).toEqual(["lib/csv.mjs", "main.mjs"]);
      const again = (await w.maestro("plugin.draft_write", { manifest: MANIFEST, files: { "lib/csv.mjs": `${LIB}// v2\n` } })) as { hash: string; files: unknown[] };
      expect(again.hash).not.toBe(v.hash);
      expect(again.files).toHaveLength(2);
      const got = (await w.maestro("plugin.draft_get", { id: "maestro.hosts-csv" })) as { code: Array<{ path: string; text: string }> };
      expect(got.code.find((f) => f.path === "main.mjs")?.text).toBe(CODE_V1);
      // Without its main file it does not validate; odd paths and dependencies are refused.
      const noMain = (await w.maestro("plugin.draft_write", { manifest: MANIFEST, remove: ["main.mjs"] })) as { valid: boolean; issues: string[] };
      expect(noMain.valid).toBe(false);
      expect(noMain.issues.join()).toMatch(/no file main\.mjs/);
      await expect(w.maestro("plugin.draft_write", { manifest: MANIFEST, files: { "../x.mjs": "x" } })).rejects.toThrow(/outside|dot/);
      await expect(w.maestro("plugin.draft_write", { manifest: MANIFEST, files: { "node_modules/a/index.js": "x" } })).rejects.toThrow(/dependencies/);
      await expect(w.maestro("plugin.draft_write", { manifest: { ...MANIFEST, level: "declarative" }, files: { "a.mjs": "x" } })).rejects.toThrow(/code plugins/);
    } finally {
      w.close();
    }
  });

  it("is tested isolated, shows the files it made, and is installed only after someone says they reviewed the code - isolated unless freed", async () => {
    const w = await world();
    try {
      await w.maestro("plugin.draft_write", { manifest: MANIFEST, files: { "main.mjs": CODE_V1, "lib/csv.mjs": LIB } });
      const test = (await w.maestro("plugin.draft_test", { id: "maestro.hosts-csv", operation: "export", input: { sep: ";" }, fixtures: { hosts: ["10.0.0.1", "10.0.0.2"] } })) as { ok: boolean; error?: string; result: unknown; files: Array<{ name: string; preview?: string }>; canPropose: boolean };
      expect(test.error).toBeUndefined();
      expect(test).toMatchObject({ ok: true, canPropose: true, result: { hosts: 2, file: "hosts.csv" } });
      expect(test.files[0]).toMatchObject({ name: "hosts.csv", preview: expect.stringContaining("10.0.0.1") });

      const proposed = (await w.maestro("plugin.draft_propose", { id: "maestro.hosts-csv", reason: "CSV of hosts", evidence: "Tested with two hosts: wrote hosts.csv with both." })) as { approvalId: string };
      const approval = (await w.human("approval.list")) as Array<{ id: string; request: { proposal: { code: { runtime: string; main: string; files: Array<{ path: string; lines: number }>; diff?: string } } } }>;
      const code = approval.find((a) => a.id === proposed.approvalId)!.request.proposal.code;
      expect(code).toMatchObject({ runtime: "node", main: "main.mjs" });
      expect(code.files.map((f) => f.path)).toEqual(["lib/csv.mjs", "main.mjs"]);
      expect(code.diff).toBeUndefined();

      // Not reviewed: refused, and the approval is still there.
      await expect(w.human("approval.approve", { approvalId: proposed.approvalId })).rejects.toThrow(/review/);
      expect(((await w.human("approval.list")) as unknown[]).length).toBe(1);
      const done = (await w.human("approval.approve", { approvalId: proposed.approvalId, plugin: { reviewedCode: true } })) as { status: string };
      expect(done.status).toBe("plugin_installed");
      expect(w.host.get("maestro.hosts-csv")).toMatchObject({ status: "active", trust: "isolated" });
      expect(existsSync(join(w.host.pluginsDir, "maestro.hosts-csv", "lib", "csv.mjs"))).toBe(true);

      w.eng.createEntity("host", { ip: "192.168.1.9", networkContext: "default" }, human);
      const r = (await w.human("plugin.run", { name: "plugin.maestro.hosts-csv.export", input: {} })) as { result: { hosts: number }; files: Array<{ name: string }> };
      expect(r.result.hosts).toBe(1);
      expect(readFileSync(join(outputDir(w.eng.dir, "maestro.hosts-csv"), "hosts.csv"), "utf8")).toBe("ip\n192.168.1.9");
    } finally {
      w.close();
    }
  });

  it("a new version is proposed with what changed, and the operator may free it", async () => {
    const w = await world();
    try {
      await w.maestro("plugin.draft_write", { manifest: MANIFEST, files: { "main.mjs": CODE_V1, "lib/csv.mjs": LIB } });
      await w.maestro("plugin.draft_test", { id: "maestro.hosts-csv", operation: "export", fixtures: { hosts: ["10.0.0.1"] } });
      const first = (await w.maestro("plugin.draft_propose", { id: "maestro.hosts-csv", reason: "v1", evidence: "Tested with one host: wrote hosts.csv with it." })) as { approvalId: string };
      await w.human("approval.approve", { approvalId: first.approvalId, plugin: { reviewedCode: true } });

      await w.maestro("plugin.draft_from_installed", { id: "maestro.hosts-csv" });
      const v2 = CODE_V1.replace('["ip"', '["ip_address"');
      await w.maestro("plugin.draft_write", { manifest: { ...MANIFEST, version: "0.2.0" }, files: { "main.mjs": v2 } });
      await w.maestro("plugin.draft_test", { id: "maestro.hosts-csv", operation: "export", fixtures: { hosts: ["10.0.0.1"] } });
      const second = (await w.maestro("plugin.draft_propose", { id: "maestro.hosts-csv", reason: "v2", evidence: "Tested with one host: the header is now ip_address." })) as { approvalId: string };
      const list = (await w.human("approval.list")) as Array<{ id: string; request: { proposal: { code: { diff?: string } } } }>;
      const diff = list.find((a) => a.id === second.approvalId)!.request.proposal.code.diff!;
      expect(diff).toContain('-    const lines = ["ip", ');
      expect(diff).toContain('+    const lines = ["ip_address", ');
      expect(diff).toContain('-  "version": "0.1.0"');
      expect(diff).not.toContain("lib/csv.mjs");
      await w.human("approval.approve", { approvalId: second.approvalId, plugin: { reviewedCode: true, trust: "free" } });
      expect(w.host.get("maestro.hosts-csv")).toMatchObject({ status: "active", version: "0.2.0", trust: "free" });
    } finally {
      w.close();
    }
  });
});

describe("a Python draft in the sandbox", () => {
  let server: Server;
  let port: number;
  beforeEach(async () => {
    server = createServer((_q, s) => s.end("reached"));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    port = (server.address() as { port: number }).port;
  });
  afterEach(async () => {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  });

  it.skipIf(spawnSync("python3", ["--version"]).status !== 0 || !offlineSandbox())("runs contained: nobody reviewed it yet, so it has no network", async () => {
    const w = await world();
    try {
      const manifest = { ...MANIFEST, id: "maestro.py-probe", main: "main.py", runtime: "python", permissions: ["files:write"], contributes: { operations: [{ name: "probe", title: "Probe", description: "probe", handler: "probe", input: [] }] } };
      const code = `import socket\n\ndef activate(plugin):\n    @plugin.operation("probe")\n    def probe(input, penteos):\n        try:\n            socket.create_connection(("127.0.0.1", ${port}), timeout=2).close()\n            net = "reached"\n        except OSError:\n            net = "blocked"\n        penteos.files.write("probe.txt", net)\n        return net\n`;
      await w.maestro("plugin.draft_write", { manifest, files: { "main.py": code } });
      const test = (await w.maestro("plugin.draft_test", { id: "maestro.py-probe", operation: "probe" })) as { ok: boolean; result: unknown; error?: string; files: Array<{ preview?: string }> };
      expect(test.error).toBeUndefined();
      expect(test.result).toBe("blocked");
      expect(test.files[0]?.preview).toBe("blocked");
    } finally {
      w.close();
    }
  });
});
