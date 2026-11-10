import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Actor, FILTERS, PluginManifest } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  declarativeActivator,
  executeOperation,
  getOperation,
  GUIDE_EXAMPLE,
  type OperationContext,
  PluginData,
  PluginDrafts,
  PluginHost,
  PluginRuntime,
  PluginSettings,
  pluginGuide,
  pluginTypes,
  ToolRegistry,
  ToolRunner,
  Workspace,
} from "../src/index.js";

/**
 * The Maestro builds plugins: drafts that are never loaded, a sandbox
 * where nothing leaves the machine and nothing touches the real catalog, and a proposal that only a
 * person turns into an installed plugin - exactly the version that was tested, in this project.
 */

const human: Actor = { type: "human", id: "01J00000000000000000000000" };
const maestro: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-builder-"));
});
afterEach(() => {
  pluginTypes.clear();
  vi.restoreAllMocks();
  rmSync(dataDir, { recursive: true, force: true });
});

async function world() {
  const ws = new Workspace(join(dataDir, "ws"));
  const data = new PluginData({ dataDir, globalVault: () => ws.vault() });
  const settings = new PluginSettings(dataDir, () => ws.vault());
  const runtime = new PluginRuntime({ data, settings, workspace: ws, fetch: (async () => {
    throw new Error("the real runtime must not be called in these tests");
  }) as typeof fetch });
  const host = new PluginHost({ dataDir, activators: { declarative: declarativeActivator(data, runtime) } });
  runtime.bind(host);
  data.bind(host);
  await host.load();
  host.bootCompleted();
  // The "real" internet for probes and live tests: crt.sh answers like crt.sh does.
  const liveCalls: string[] = [];
  const live = (async (input: string | URL | Request) => {
    liveCalls.push(String(input));
    if (String(input).startsWith("https://crt.sh/")) return new Response(JSON.stringify(CRT), { headers: { "content-type": "application/json" } });
    return new Response("Error valid key required", { status: 200, headers: { "content-type": "text/plain" } });
  }) as typeof fetch;
  const drafts = new PluginDrafts(dataDir, host, live);
  const eng = ws.create({ clientName: "ACME", name: "Recon", mode: "web" }, human);
  const other = ws.create({ clientName: "ACME", name: "Otro", mode: "web" }, human);
  const runners = new Map<string, ToolRunner>();
  const runnerFor = (id: string) => {
    let r = runners.get(id);
    if (!r) {
      r = new ToolRunner(ws.get(id), new ToolRegistry(join(dataDir, "tools")));
      r.pluginInstall = (proposal, by) => drafts.install(proposal, ws.get(id), by);
      runners.set(id, r);
    }
    return r;
  };
  const ctx = (actor: Actor): OperationContext =>
    ({
      workspace: ws,
      caller: { actor, policy: { type: actor.type === "agent" ? "agent" : "human", autonomy: "autonomous", maxRisk: "active" } },
      defaultEngagementId: eng.info.id,
      engagement: (id?: string) => ws.get(id ?? eng.info.id),
      runner: (id?: string) => runnerFor(id ?? eng.info.id),
      plugins: host,
      pluginData: data,
      pluginRuntime: runtime,
      pluginSettings: settings,
      pluginDrafts: drafts,
    }) as unknown as OperationContext;
  const as = (actor: Actor) => (op: string, input: Record<string, unknown> = {}) => executeOperation(op, input, ctx(actor));
  return { ws, host, drafts, eng, other, liveCalls, maestro: as(maestro), human: as(human), close: () => ws.close() };
}

const CRT = [
  { name_value: "www.acme.test\nmail.acme.test", issuer_name: "R3" },
  { name_value: "api.acme.test", issuer_name: "R3" },
  { name_value: "WWW.acme.test", issuer_name: "R3" },
];

describe("the guide", () => {
  it("documents every filter and its example validates as is", () => {
    const guide = pluginGuide();
    for (const f of Object.keys(FILTERS)) expect(guide, `filter ${f} missing from the guide`).toMatch(new RegExp(`\\b${f}\\b`));
    const r = PluginManifest.safeParse(GUIDE_EXAMPLE);
    expect(r.success ? "" : r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(" | ")).toBe("");
  });
});

describe("drafts", () => {
  it("are always maestro.*, by the Maestro, declarative unless they say code, and keep invalid JSON with exact issues", async () => {
    const w = await world();
    try {
      const v = (await w.maestro("plugin.draft_write", { manifest: { ...GUIDE_EXAMPLE, id: "acme.crtsh", level: undefined, author: { type: "human", name: "Someone" }, main: "x.js" } })) as { id: string; valid: boolean; warnings: string[] };
      expect(v.id).toBe("maestro.crtsh");
      expect(v.valid).toBe(true);
      expect(v.warnings.join(" ")).toMatch(/id set to maestro.crtsh/);
      const saved = JSON.parse(readFileSync(join(dataDir, "plugin-drafts", "maestro.crtsh", "plugin.json"), "utf8"));
      expect(saved).toMatchObject({ author: { type: "maestro" }, level: "declarative" });
      expect(saved.main).toBeUndefined();
      // A draft is never loaded as a plugin.
      expect(w.host.get("maestro.crtsh")).toBeUndefined();

      const bad = (await w.maestro("plugin.draft_write", { manifest: { ...GUIDE_EXAMPLE, permissions: ["graph:read"] } })) as { valid: boolean; issues: string[] };
      expect(bad.valid).toBe(false);
      expect(bad.issues.join("\n")).toMatch(/contributes.operations.0.steps.0.url: crt.sh is not in the plugin's net/);
    } finally {
      w.close();
    }
  });
});

describe("the sandbox", () => {
  it("runs with recorded responses only, reports every step, and touches nothing real", async () => {
    const w = await world();
    const realFetch = vi.spyOn(globalThis, "fetch");
    try {
      await w.maestro("plugin.draft_write", { manifest: GUIDE_EXAMPLE });
      const report = (await w.maestro("plugin.draft_test", {
        id: "maestro.crtsh",
        operation: "subdomains",
        input: { domain: "{{fixtures.domains[0].fqdn}}" },
        fixtures: { domains: ["acme.test"] },
        responses: [{ url: "https://crt.sh/", body: CRT }],
      })) as { ok: boolean; result: { count: number; names: Array<{ name: string }> }; steps: Array<{ do: string; ok: boolean }>; requests: Array<{ url: string; matched: boolean }>; wrote: { entities: Array<{ kind: string; naturalKey: string }> }; canPropose: boolean };
      expect(report.ok).toBe(true);
      expect(report.result.count).toBe(3);
      expect(report.result.names.map((n) => n.name).sort()).toEqual(["api.acme.test", "mail.acme.test", "www.acme.test"]);
      expect(report.steps.map((s) => s.do)).toEqual(["http", "set", "put", "put", "put", "each", "store_insert"]);
      expect(report.requests).toEqual([expect.objectContaining({ url: "https://crt.sh/?q=%25.acme.test&output=json", matched: true })]);
      expect(report.wrote.entities.map((e) => e.naturalKey).sort()).toEqual(["api.acme.test", "mail.acme.test", "www.acme.test"]);
      // Recorded answers only: it cannot be proposed until it worked against the real service.
      expect(report.canPropose).toBe(false);
      const live = (await w.maestro("plugin.draft_test", { id: "maestro.crtsh", operation: "subdomains", input: { domain: "acme.test" }, live: true, expect: { fields: ["count", "names[0].name"], contains: ["www.acme.test"] } })) as { ok: boolean; live: boolean; canPropose: boolean; expectations: Array<{ ok: boolean }> };
      expect(live).toMatchObject({ ok: true, live: true, canPropose: true });
      expect(live.expectations.every((x) => x.ok)).toBe(true);
      expect(w.liveCalls).toEqual(["https://crt.sh/?q=%25.acme.test&output=json"]);

      // Nothing real: no request left, no type or tool registered, no data in the real project.
      expect(realFetch).not.toHaveBeenCalled();
      expect(pluginTypes.type("maestro.crtsh:ct_name")).toBeUndefined();
      expect(getOperation("plugin.maestro.crtsh.subdomains")).toBeUndefined();
      expect(w.eng.counts()["maestro.crtsh:ct_name"]).toBeUndefined();
    } finally {
      w.close();
    }
  });

  it("shows where a failure happened, and a request with no recorded answer is never sent", async () => {
    const w = await world();
    try {
      await w.maestro("plugin.draft_write", { manifest: GUIDE_EXAMPLE });
      const r404 = (await w.maestro("plugin.draft_test", { id: "maestro.crtsh", operation: "subdomains", input: { domain: "acme.test" }, responses: [{ url: "https://crt.sh/", status: 502, body: "Bad gateway" }] })) as { ok: boolean; error: string; steps: Array<{ path: string; ok: boolean; error?: string }>; canPropose: boolean };
      expect(r404.ok).toBe(false);
      expect(r404.error).toMatch(/step 1 \(http r\): crt.sh answered 502/);
      expect(r404.steps).toEqual([expect.objectContaining({ path: "1", ok: false })]);
      expect(r404.canPropose).toBe(false);

      const none = (await w.maestro("plugin.draft_test", { id: "maestro.crtsh", operation: "subdomains", input: { domain: "acme.test" } })) as { ok: boolean; error: string; requests: Array<{ matched: boolean }> };
      expect(none.error).toMatch(/no recorded response for GET https:\/\/crt.sh/);
      expect(none.requests).toEqual([expect.objectContaining({ matched: false })]);

      // The loop guard still works: the same test of the same draft, a third time, is echoed.
      await w.maestro("plugin.draft_test", { id: "maestro.crtsh", operation: "subdomains", input: { domain: "acme.test" } });
      const third = (await w.maestro("plugin.draft_test", { id: "maestro.crtsh", operation: "subdomains", input: { domain: "acme.test" } })) as { repeatedCall?: string };
      expect(third.repeatedCall).toBeTruthy();
    } finally {
      w.close();
    }
  });
});

describe("proposing and installing", () => {
  it("only a tested version can be proposed; only a person installs it, exactly as tested, in this project", async () => {
    const w = await world();
    try {
      await w.maestro("plugin.draft_write", { manifest: GUIDE_EXAMPLE });
      await expect(w.maestro("plugin.draft_propose", { id: "maestro.crtsh", reason: "Subdominios pasivos", evidence: "Probado en vivo con acme.test: devolvió 3 subdominios." })).rejects.toThrow(/test this exact version/);
      await w.maestro("plugin.draft_test", { id: "maestro.crtsh", operation: "subdomains", input: { domain: "acme.test" }, responses: [{ url: "https://crt.sh/", body: CRT }] });
      // Tested only against answers it wrote itself: not enough for something that talks to the internet.
      await expect(w.maestro("plugin.draft_propose", { id: "maestro.crtsh", reason: "Subdominios pasivos", evidence: "Probado en vivo con acme.test: devolvió 3 subdominios." })).rejects.toThrow(/against the real service/);
      const test = { id: "maestro.crtsh", operation: "subdomains", input: { domain: "acme.test" }, live: true, expect: { contains: ["www.acme.test"] } };
      await w.maestro("plugin.draft_test", test);
      const proposed = (await w.maestro("plugin.draft_propose", { id: "maestro.crtsh", reason: "Subdominios pasivos", evidence: "Probado en vivo con acme.test: devolvió 3 subdominios." })) as { status: string; approvalId: string };
      expect(proposed.status).toBe("pending_approval");
      const card = (await w.human("approval.list", {})) as Array<{ id: string; request: { kind: string; proposal: { permissions: string[]; sendsTo: string[]; test: { operation: string } } } }>;
      expect(card[0]!.request).toMatchObject({ kind: "plugin", proposal: { sendsTo: ["crt.sh"], permissions: ["net:crt.sh", "graph:read", "graph:write", "ui:menu"], test: { operation: "subdomains" }, evidence: expect.stringContaining("acme.test"), live: { input: { domain: "acme.test" }, requests: ["GET https://crt.sh/?q=%25.acme.test&output=json → 200"], checks: ['contains "www.acme.test"'] } } });

      // The Maestro can neither install nor approve.
      await expect(w.maestro("approval.approve", { approvalId: proposed.approvalId })).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
      await expect(w.maestro("plugin.install", { id: "maestro.crtsh" })).rejects.toMatchObject({ code: "PERMISSION_DENIED" });

      // Changed after the proposal: approving installs nothing.
      const file = join(dataDir, "plugin-drafts", "maestro.crtsh", "plugin.json");
      writeFileSync(file, readFileSync(file, "utf8").replace('"crt.sh subdomains"', '"crt.sh subdomains v2"'));
      await expect(w.human("approval.approve", { approvalId: proposed.approvalId })).rejects.toThrow(/changed after it was proposed/);
      expect(w.host.get("maestro.crtsh")).toBeUndefined();

      await w.maestro("plugin.draft_test", test);
      const again = (await w.maestro("plugin.draft_propose", { id: "maestro.crtsh", reason: "Subdominios pasivos", evidence: "Probado en vivo con acme.test: devolvió 3 subdominios." })) as { approvalId: string };
      const installed = await w.human("approval.approve", { approvalId: again.approvalId });
      expect(installed).toMatchObject({ status: "plugin_installed", pluginId: "maestro.crtsh", version: "0.1.0" });
      expect(w.host.get("maestro.crtsh")).toMatchObject({ status: "active", author: { type: "maestro" } });
      expect(w.eng.info.plugins).toContain("maestro.crtsh");
      expect(w.other.info.plugins).not.toContain("maestro.crtsh");
      expect(getOperation("plugin.maestro.crtsh.subdomains")?.actors).toContain("agent");

      // A new version must say so.
      await w.maestro("plugin.draft_from_installed", { id: "maestro.crtsh" });
      await w.maestro("plugin.draft_test", test);
      await expect(w.maestro("plugin.draft_propose", { id: "maestro.crtsh", reason: "v2", evidence: "Probado en vivo con acme.test: devolvió 3 subdominios." })).rejects.toThrow(/not above the installed 0.1.0/);
    } finally {
      w.close();
    }
  });
});
