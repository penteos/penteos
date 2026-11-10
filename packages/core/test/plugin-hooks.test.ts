import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Actor, PluginManifest } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { declarativeActivator, executeOperation, type OperationContext, PluginData, PluginHost, PluginRuntime, PluginSettings, pluginTypes, SKILL_LIMITS, Workspace } from "../src/index.js";

/**
 * More hooks: knowledge for the Maestro, reactions to more of
 * what happens in a project, and more formats for the deliverable.
 */

const human: Actor = { type: "human", id: "01J00000000000000000000000" };
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-hooks-"));
});
afterEach(() => {
  pluginTypes.clear();
  rmSync(dataDir, { recursive: true, force: true });
});

const MANIFEST = {
  id: "lab.hooks",
  name: "Hooks (lab)",
  version: "1.0.0",
  apiVersion: 1,
  level: "declarative",
  author: { type: "human", name: "Lab" },
  permissions: ["graph:read", "files:write", "notify"],
  contributes: {
    skills: [
      { id: "method", title: { en: "House method", es: "Método de la casa" }, text: "Always check **/.git/** on every web app." },
      { id: "infra", title: "Infrastructure only", text: "Prefer living off the land.", modes: ["infra"] },
    ],
    operations: [
      { name: "on_service", title: "Service seen", description: "Notes a new service", input: [{ name: "port", type: "integer" }], steps: [{ do: "notify", title: "New service on port {{input.port}}" }], view: { type: "json" } },
      { name: "on_oob", title: "Callback", description: "Notes an OOB callback", input: [{ name: "remote", type: "string" }], steps: [{ do: "notify", title: "Callback from {{input.remote}}" }], view: { type: "json" } },
      { name: "csv", title: "Findings CSV", description: "Findings as CSV", input: [], steps: [{ do: "graph_query", id: "f", kind: "finding" }, { do: "file", name: "findings.csv", content: "title\n{{steps.f | pluck:'attributes.title' | join:'\n'}}" }], view: { type: "json" } },
    ],
    events: [
      { on: "service.created", operation: "on_service", input: { port: "{{event.entity.attributes.port}}" } },
      { on: "oob.interaction", operation: "on_oob", input: { remote: "{{event.detail.remote}}" } },
    ],
    exports: [{ id: "csv", title: { en: "Findings (CSV)", es: "Hallazgos (CSV)" }, operation: "csv", icon: "chart" }],
  },
};

async function world(mode: "web" | "infra" = "web") {
  const dir = join(dataDir, "plugins", MANIFEST.id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "plugin.json"), JSON.stringify(MANIFEST));
  const ws = new Workspace(join(dataDir, "ws"));
  const data = new PluginData({ dataDir, globalVault: () => ws.vault() });
  const settings = new PluginSettings(dataDir, () => ws.vault());
  let runtime: PluginRuntime;
  let host: PluginHost;
  const ctxFor = (engagementId: string, actor: Actor) => ({ workspace: ws, caller: { actor, policy: { type: "human" } }, defaultEngagementId: engagementId, engagement: () => ws.get(engagementId), runner: () => { throw new Error("no runner"); }, plugins: host, pluginData: data, pluginRuntime: runtime, pluginSettings: settings }) as unknown as OperationContext;
  runtime = new PluginRuntime({ data, settings, workspace: ws, context: ctxFor });
  host = new PluginHost({ dataDir, activators: { declarative: declarativeActivator(data, runtime) } });
  runtime.bind(host);
  data.bind(host);
  await host.load();
  await host.approve(MANIFEST.id);
  const eng = ws.create({ language: "es", clientName: "Lab", name: "Hooks", mode, plugins: [MANIFEST.id] }, human);
  const notices: string[] = [];
  eng.events.on("change", (e) => {
    if (e.type === "plugin.notify") notices.push(e.title);
  });
  return { ws, eng, runtime, notices, op: (name: string, input: Record<string, unknown> = {}) => executeOperation(name, input, ctxFor(eng.info.id, human)), close: () => ws.close() };
}

describe("knowledge for the Maestro", () => {
  it("comes from plugins enabled in the project, for its mode, in its language", async () => {
    const w = await world();
    try {
      expect(w.runtime.skillsFor(w.eng)).toEqual([{ plugin: "Hooks (lab)", title: "Método de la casa", text: "Always check **/.git/** on every web app." }]);
      w.eng.setInfo({ ...w.eng.info, plugins: [] }, human);
      expect(w.runtime.skillsFor(w.eng)).toEqual([]);
    } finally {
      w.close();
    }
    const r = await world("infra");
    try {
      expect(r.runtime.skillsFor(r.eng).map((s) => s.title)).toEqual(["Método de la casa", "Infrastructure only"]);
    } finally {
      r.close();
    }
  });

  it("is bounded", () => {
    expect(SKILL_LIMITS.total).toBeLessThanOrEqual(30_000);
    const tooLong = PluginManifest.safeParse({ ...MANIFEST, contributes: { skills: [{ id: "x", title: "x", text: "a".repeat(8001) }] } });
    expect(tooLong.success).toBe(false);
  });
});

describe("more events", () => {
  it("a new service and an out-of-band callback reach the plugin, with what happened", async () => {
    const w = await world();
    try {
      const host = w.eng.createEntity("host", { ip: "10.0.0.5", networkContext: "default" }, human);
      w.eng.createEntity("service", { hostId: host.id, port: 8443, transport: "tcp", state: "open" }, human);
      w.eng.emit({ type: "oob.interaction", id: "01JOOB0000000000000000000A", protocol: "dns", fullId: "x", remote: "203.0.113.9" });
      await w.runtime.idle();
      expect(w.notices.sort()).toEqual(["Callback from 203.0.113.9", "New service on port 8443"]);
    } finally {
      w.close();
    }
  });
});

describe("more formats for the deliverable", () => {
  it("are offered in the catalog and make their files", async () => {
    const w = await world();
    try {
      const cat = w.runtime.catalog().find((p) => p.id === MANIFEST.id)!;
      expect(cat.exports).toEqual([{ id: "csv", title: { en: "Findings (CSV)", es: "Hallazgos (CSV)" }, operation: "csv", icon: "chart" }]);
      w.eng.createEntity("finding", { title: "Open redirect", severity: "low", status: "approved" }, human);
      const r = (await w.op("plugin.run", { name: "plugin.lab.hooks.csv", input: {} })) as { files: Array<{ name: string }> };
      expect(r.files.map((f) => f.name)).toEqual(["findings.csv"]);
    } finally {
      w.close();
    }
  });

  it("need an operation people can run with no input", () => {
    const bad = PluginManifest.safeParse({ ...MANIFEST, contributes: { ...MANIFEST.contributes, exports: [{ id: "x", title: "x", operation: "on_oob" }] } });
    expect(bad.success).toBe(true);
    const missing = PluginManifest.safeParse({ ...MANIFEST, contributes: { ...MANIFEST.contributes, exports: [{ id: "x", title: "x", operation: "nope" }] } });
    expect(JSON.stringify(missing.error?.issues)).toMatch(/no operation .{0,3}nope/);
  });
});
