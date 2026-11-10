import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type ChangeEvent,
  declarativeActivator,
  executeOperation,
  type OperationContext,
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
 * How the Maestro builds a plugin the way a careful engineer would: it looks at the real service
 * first, tests against it with acceptance criteria, asks the operator for what only they can give
 * (a key it never sees), and hears when a plugin it built fails for the operator.
 */

const human: Actor = { type: "human", id: "01J00000000000000000000000" };
const maestro: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-method-"));
});
afterEach(() => {
  pluginTypes.clear();
  rmSync(dataDir, { recursive: true, force: true });
});

/** The "real" internet: a WHOIS API that wants a key, RDAP that redirects, a key-checked API. */
function internet() {
  const seen: Array<{ url: string; headers: Record<string, string> }> = [];
  const fetchImpl = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(String(input));
    const headers = Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]));
    seen.push({ url: url.href, headers });
    if (url.hostname === "api.whois.test") return new Response("error valid key required", { status: 200, headers: { "content-type": "text/plain" } });
    if (url.hostname === "rdap.test") return new Response(null, { status: 302, headers: { location: "https://rdap.registry.test/domain/news.example" } });
    if (url.hostname === "api.geo.test") {
      if (headers["x-key"] !== "REAL-KEY-12345") return new Response(JSON.stringify({ error: "invalid key" }), { status: 401, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ ip: url.pathname.split("/").pop(), country: "AR", city: "Buenos Aires" }), { headers: { "content-type": "application/json" } });
    }
    return new Response("nothing here", { status: 404 });
  }) as typeof fetch;
  return { fetchImpl, seen };
}

async function world() {
  const net = internet();
  const ws = new Workspace(join(dataDir, "ws"));
  const data = new PluginData({ dataDir, globalVault: () => ws.vault() });
  const settings = new PluginSettings(dataDir, () => ws.vault());
  const runtime = new PluginRuntime({ data, settings, workspace: ws, fetch: net.fetchImpl });
  const host = new PluginHost({ dataDir, activators: { declarative: declarativeActivator(data, runtime) } });
  runtime.bind(host);
  data.bind(host);
  await host.load();
  host.bootCompleted();
  const drafts = new PluginDrafts(dataDir, host, net.fetchImpl);
  const eng = ws.create({ clientName: "ACME", name: "Recon", mode: "web" }, human);
  eng.addScopeRule({ effect: "include", target: { type: "domain", value: "acme.test" } } as never, human);
  const events: ChangeEvent[] = [];
  eng.events.on("change", (e: ChangeEvent) => events.push(e));
  let runner: ToolRunner | undefined;
  const ctx = (actor: Actor): OperationContext =>
    ({
      workspace: ws,
      caller: { actor, policy: { type: actor.type === "agent" ? "agent" : "human", autonomy: "autonomous", maxRisk: "active" } },
      defaultEngagementId: eng.info.id,
      engagement: () => eng,
      runner: () => {
        if (!runner) {
          runner = new ToolRunner(eng, new ToolRegistry(join(dataDir, "tools")));
          runner.pluginInstall = (proposal, by, options) => drafts.install(proposal, eng, by, options);
        }
        return runner;
      },
      plugins: host,
      pluginData: data,
      pluginRuntime: runtime,
      pluginSettings: settings,
      pluginDrafts: drafts,
    }) as unknown as OperationContext;
  const as = (actor: Actor) => (op: string, input: Record<string, unknown> = {}) => executeOperation(op, input, ctx(actor));
  return { ws, eng, host, net, events, maestro: as(maestro), human: as(human), close: () => ws.close() };
}

const GEO = {
  id: "maestro.geo",
  name: "Geolocalizar IP",
  version: "0.1.0",
  level: "declarative",
  permissions: ["net:api.geo.test"],
  contributes: {
    settings: [{ name: "apiKey", type: "string", secret: true, required: true, label: "Clave de Geo" }],
    operations: [
      {
        name: "locate",
        title: "Locate",
        description: "Where an IP is",
        input: [{ name: "ip", type: "string", required: true }],
        steps: [
          { do: "fail", if: "{{input.ip | private_ip}}", message: "{{input.ip}} es una dirección privada: no tiene ubicación pública." },
          { do: "http", id: "r", url: "https://api.geo.test/ip/{{input.ip}}", headers: { "X-Key": "{{settings.apiKey}}" } },
        ],
        result: "{{steps.r.body}}",
        view: { type: "card", fields: [{ field: "country", label: "País" }, { field: "city", label: "Ciudad" }] },
      },
    ],
  },
};

describe("looking at the real service first", () => {
  it("shows what it really answers, and says what to notice: a key it wants, an error behind a 200, a redirect to another host", async () => {
    const w = await world();
    try {
      const whois = (await w.maestro("plugin.probe", { url: "https://api.whois.test/whois/?q=news.example" })) as { status: number; body: unknown; hints: string[]; probeId: string };
      expect(whois).toMatchObject({ status: 200, body: "error valid key required" });
      expect(whois.hints.join("\n")).toMatch(/needs a key/);
      expect(whois.hints.join("\n")).toMatch(/status 200 but the body reads like an error/);
      const rdap = (await w.maestro("plugin.probe", { url: "https://rdap.test/domain/news.example" })) as { status: number; location: string; hints: string[] };
      expect(rdap).toMatchObject({ status: 302, location: "https://rdap.registry.test/domain/news.example" });
      expect(rdap.hints.join("\n")).toMatch(/another host \(rdap.registry.test\)/);
      expect(w.eng.auditEvents({ limit: 50 }).filter((a) => a.action === "plugin.probe")).toHaveLength(2);
    } finally {
      w.close();
    }
  });

  it("never a project target nor a private network", async () => {
    const w = await world();
    try {
      await expect(w.maestro("plugin.probe", { url: "https://acme.test/" })).rejects.toThrow(/target of this project/);
      await expect(w.maestro("plugin.probe", { url: "http://192.168.1.1/" })).rejects.toThrow(/private network/);
      await expect(w.maestro("plugin.probe", { url: "http://localhost:8080/" })).rejects.toThrow(/private network/);
      expect(w.net.seen).toHaveLength(0);
    } finally {
      w.close();
    }
  });
});

describe("asking the operator for what only they have", () => {
  it("a key is asked for, given in a protected field, used live - and the Maestro never sees it", async () => {
    const w = await world();
    try {
      await w.maestro("plugin.draft_write", { manifest: GEO });
      const noKey = (await w.maestro("plugin.draft_test", { id: "maestro.geo", operation: "locate", input: { ip: "8.8.8.8" }, live: true })) as { ok: boolean; error: string };
      expect(noKey.ok).toBe(false);
      expect(noKey.error).toMatch(/plugin_draft_request_setting/);
      await expect(w.maestro("plugin.draft_propose", { id: "maestro.geo", reason: "geo", evidence: "Not tested yet against the service." })).rejects.toThrow();

      await expect(w.maestro("plugin.draft_request_setting", { id: "maestro.geo", setting: "nope", reason: "x is needed" })).rejects.toThrow(/no setting "nope"/);
      const asked = (await w.maestro("plugin.draft_request_setting", { id: "maestro.geo", setting: "apiKey", reason: "El servicio de geolocalización pide una clave gratuita" })) as { status: string };
      expect(asked.status).toBe("asked");
      expect(w.events.find((e) => e.type === "plugin.setting_requested")).toMatchObject({ draftId: "maestro.geo", setting: "apiKey", label: "Clave de Geo", secret: true });
      await expect(w.maestro("plugin.draft_propose", { id: "maestro.geo", reason: "geo", evidence: "Not tested yet against the service." })).rejects.toThrow(/waits for the operator's apiKey/);
      // Only a person gives it.
      await expect(w.maestro("plugin.draft_set_settings", { id: "maestro.geo", values: { apiKey: "mine" } })).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
      await w.human("plugin.draft_set_settings", { id: "maestro.geo", values: { apiKey: "REAL-KEY-12345" } });
      expect(w.events.find((e) => e.type === "plugin.setting_given")).toMatchObject({ draftId: "maestro.geo", settings: ["apiKey"] });
      expect(JSON.stringify(w.events)).not.toContain("REAL-KEY-12345");

      const live = (await w.maestro("plugin.draft_test", { id: "maestro.geo", operation: "locate", input: { ip: "8.8.8.8" }, live: true, expect: { fields: ["country", "city"] } })) as { ok: boolean; result: unknown; canPropose: boolean };
      expect(live).toMatchObject({ ok: true, result: { country: "AR", city: "Buenos Aires" }, canPropose: true });
      expect(w.net.seen.at(-1)?.headers["x-key"]).toBe("REAL-KEY-12345");
      expect(JSON.stringify(live)).not.toContain("REAL-KEY-12345");
      // A probe with the operator's key: used, never shown.
      const probe = (await w.maestro("plugin.probe", { url: "https://api.geo.test/ip/1.1.1.1", headers: { "X-Key": "{{settings.apiKey}}" }, draft: "maestro.geo" })) as { status: number };
      expect(probe.status).toBe(200);
      expect(JSON.stringify(w.eng.auditEvents({ limit: 100 }))).not.toContain("REAL-KEY-12345");
      const view = (await w.human("plugin.draft_settings", { id: "maestro.geo" })) as { secretsSet: string[]; needs: unknown[] };
      expect(view).toMatchObject({ secretsSet: ["apiKey"], needs: [] });
    } finally {
      w.close();
    }
  });
});

describe("acceptance criteria", () => {
  it("a test passes only if the result shows what was asked; a failure path passes only with a true, clear message", async () => {
    const w = await world();
    try {
      await w.maestro("plugin.draft_write", { manifest: GEO });
      await w.human("plugin.draft_set_settings", { id: "maestro.geo", values: { apiKey: "REAL-KEY-12345" } });
      const missing = (await w.maestro("plugin.draft_test", { id: "maestro.geo", operation: "locate", input: { ip: "8.8.8.8" }, live: true, expect: { fields: ["country", "registrar"] } })) as { ok: boolean; expectations: Array<{ check: string; ok: boolean }>; canPropose: boolean };
      expect(missing.ok).toBe(false);
      expect(missing.expectations).toEqual([{ check: "result.country has a value", ok: true }, { check: "result.registrar has a value", ok: false }]);
      expect(missing.canPropose).toBe(false);
      const priv = (await w.maestro("plugin.draft_test", { id: "maestro.geo", operation: "locate", input: { ip: "10.0.0.1" }, expect: { fails: true } })) as { ok: boolean; error: string };
      expect(priv.ok).toBe(true);
      // The plugin's own words reach the person as they are.
      expect(priv.error).toBe("Geolocalizar IP: 10.0.0.1 es una dirección privada: no tiene ubicación pública.");
      // Recorded answers it wrote itself are called out; ones from a probe are not.
      const probe = (await w.maestro("plugin.probe", { url: "https://api.geo.test/ip/9.9.9.9" })) as { probeId: string };
      const replay = (await w.maestro("plugin.draft_test", { id: "maestro.geo", operation: "locate", input: { ip: "9.9.9.9" }, responses: [{ fromProbe: probe.probeId }], expect: { fails: true } })) as { invented: number; error: string; warning?: string };
      expect(replay.invented).toBe(0);
      expect(replay.warning).toBeUndefined();
      expect(replay.error).toMatch(/401/);
      const made = (await w.maestro("plugin.draft_test", { id: "maestro.geo", operation: "locate", input: { ip: "9.9.9.9" }, responses: [{ url: "https://api.geo.test/", body: { country: "XX" } }] })) as { invented: number; warning: string; review: string[] };
      expect(made.invented).toBe(1);
      expect(made.warning).toMatch(/prove nothing/);
      expect(made.review.length).toBeGreaterThan(3);
    } finally {
      w.close();
    }
  });
});

describe("a plugin the Maestro built fails for the operator", () => {
  it("the Maestro hears it, with the input and the error", async () => {
    const w = await world();
    try {
      await w.maestro("plugin.draft_write", { manifest: GEO });
      await w.human("plugin.draft_set_settings", { id: "maestro.geo", values: { apiKey: "REAL-KEY-12345" } });
      await w.maestro("plugin.draft_test", { id: "maestro.geo", operation: "locate", input: { ip: "8.8.8.8" }, live: true, expect: { fields: ["country"] } });
      const p = (await w.maestro("plugin.draft_propose", { id: "maestro.geo", reason: "geo", evidence: "Probado en vivo con 8.8.8.8: devolvió AR, Buenos Aires." })) as { approvalId: string };
      await w.human("approval.approve", { approvalId: p.approvalId });
      w.eng.setInfo({ ...w.eng.info, plugins: ["maestro.geo"] }, human);
      // The key stops working (revoked, changed): the operator runs it and it fails.
      await w.human("plugin.set_settings", { id: "maestro.geo", values: { apiKey: "REVOKE0" } });
      await expect(w.human("plugin.run", { name: "plugin.maestro.geo.locate", input: { ip: "8.8.4.4" } })).rejects.toThrow(/401/);
      expect(w.events.find((e) => e.type === "plugin.failed")).toMatchObject({ pluginId: "maestro.geo", operation: "locate", input: { ip: "8.8.4.4" }, error: expect.stringMatching(/401/) });
    } finally {
      w.close();
    }
  });
});
