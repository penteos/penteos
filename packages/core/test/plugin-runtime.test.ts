import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Actor, PluginManifest, renderValue, SecretValue, TemplateError } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  declarativeActivator,
  executeOperation,
  getOperation,
  type OperationContext,
  PluginData,
  PluginHost,
  PluginRuntime,
  PluginSettings,
  pluginTypes,
  Workspace,
} from "../src/index.js";

/**
 * Declarative plugins at work, against a fake internet. What every test
 * checks: a plugin does what its manifest says and nothing else - only its hosts, only where it was
 * enabled, never showing a secret, never looping, and a misbehaving one ends up off.
 */

const human: Actor = { type: "human", id: "01J00000000000000000000000" };
const agent: Actor = { type: "agent", id: "01J00000000000000000000001" };
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-plugin-run-"));
});
afterEach(() => {
  pluginTypes.clear();
  rmSync(dataDir, { recursive: true, force: true });
});

const base = { name: "Lab plugin", version: "1.0.0", apiVersion: 1, level: "declarative", author: { type: "human" } };

const SHODAN = {
  ...base,
  id: "lab.shodan",
  name: "Shodan (lab)",
  permissions: ["net:api.shodan.test", "graph:read", "graph:write", "ui:menu", "notify", "findings:draft"],
  contributes: {
    settings: [{ name: "apiKey", type: "string", secret: true, label: { es: "Clave de API", en: "API key" } }],
    entityTypes: [
      {
        name: "banner",
        label: "Banner",
        fields: [
          { name: "ip", type: "host", required: true },
          { name: "port", type: "integer", required: true },
          { name: "product", type: "string" },
        ],
        key: ["ip", "port"],
        target: "ip",
      },
    ],
    annotations: [{ on: ["host"], fields: [{ name: "org", type: "string" }, { name: "ports", type: "json" }] }],
    operations: [
      {
        name: "lookup",
        title: { es: "Consultar Shodan", en: "Shodan lookup" },
        description: "Looks up an IP in Shodan and records its open ports and banners.",
        input: [{ name: "ip", type: "host", required: true }],
        steps: [
          { do: "http", id: "r", url: "https://api.shodan.test/shodan/host/{{input.ip}}", query: { key: "{{settings.apiKey}}" }, expect: [200, 404] },
          { do: "fail", if: "{{steps.r.status | eq:404}}", message: "Shodan has nothing on {{input.ip}}" },
          { do: "graph_query", id: "hosts", kind: "host", text: "{{input.ip}}" },
          {
            do: "each",
            id: "banners",
            over: "{{steps.r.body.data}}",
            as: "svc",
            steps: [{ do: "put", type: "banner", attributes: { ip: "{{input.ip}}", port: "{{svc.port}}", product: "{{svc.product | default:'unknown'}}" }, relate: "{{steps.hosts[0].id}}" }],
            collect: "{{svc.port}}",
          },
          { do: "annotate", if: "{{steps.hosts | length | gt:0}}", entity: "{{steps.hosts[0].id}}", data: { org: "{{steps.r.body.org}}", ports: "{{steps.banners}}" } },
        ],
        result: { ip: "{{input.ip}}", org: "{{steps.r.body.org}}", ports: "{{steps.banners}}", echoed: "{{steps.r.body.echo}}" },
        view: { type: "card", fields: [{ field: "org", label: "Org" }, { field: "ports", label: "Ports" }] },
      },
      {
        name: "flag",
        title: "Flag exposed SSH",
        description: "Drafts a finding when a host exposes SSH to the internet.",
        actors: ["human"],
        input: [{ name: "host", type: "string", required: true }],
        steps: [{ do: "finding_draft", title: "SSH exposed to the internet", severity: "low", affects: ["{{input.host}}"] }],
      },
      {
        name: "ping",
        title: "Notify",
        description: "Tells the operator a finding appeared.",
        actors: ["human"],
        input: [{ name: "title", type: "string" }],
        steps: [{ do: "notify", title: "New finding: {{input.title}}" }],
      },
    ],
    menus: [{ id: "lookup_host", title: "Shodan", operation: "lookup", where: "entity", kinds: ["host"], prefill: { ip: "{{entity.attributes.ip}}" } }],
    events: [{ on: "finding.created", operation: "ping", input: { title: "{{event.entity.attributes.title}}" } }],
  },
};

interface FakeCall {
  url: string;
  init: RequestInit;
}

/** A fake internet: each host answers with the given function. */
function internet(routes: Record<string, (url: URL, init: RequestInit) => Response | Promise<Response>>) {
  const calls: FakeCall[] = [];
  const fetchImpl = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(String(input));
    calls.push({ url: url.toString(), init });
    const route = routes[url.hostname];
    if (!route) throw new Error(`fake internet: nothing at ${url.hostname}`);
    return route(url, init);
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

async function world(manifest: Record<string, unknown>, fetchImpl: typeof fetch, opts: { approve?: boolean } = {}) {
  const dir = join(dataDir, "plugins", String(manifest.id));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "plugin.json"), JSON.stringify(manifest));
  const ws = new Workspace(join(dataDir, "ws"));
  const data = new PluginData({ dataDir, globalVault: () => ws.vault() });
  const settings = new PluginSettings(dataDir, () => ws.vault());
  let ctxFor: (id: string, actor: Actor) => OperationContext = () => {
    throw new Error("not ready");
  };
  const runtime = new PluginRuntime({ data, settings, workspace: ws, fetch: fetchImpl, context: (id, actor) => ctxFor(id, actor) });
  const host = new PluginHost({ dataDir, activators: { declarative: declarativeActivator(data, runtime) }, activationBudgetMs: 2000 });
  runtime.bind(host);
  data.bind(host);
  await host.load();
  if (opts.approve !== false) await host.approve(String(manifest.id));
  const eng = ws.create({ clientName: "ACME", name: "Infra", mode: "infra" }, human);
  const ctx = (actor: Actor = human): OperationContext =>
    ({
      workspace: ws,
      caller: { actor, policy: { type: actor.type === "agent" ? "agent" : "human", autonomy: "autonomous", maxRisk: "active" } },
      defaultEngagementId: eng.info.id,
      engagement: (id?: string) => ws.get(id ?? eng.info.id),
      runner: () => {
        throw new Error("no runner");
      },
      plugins: host,
      pluginData: data,
      pluginRuntime: runtime,
      pluginSettings: settings,
    }) as unknown as OperationContext;
  ctxFor = (_id, actor) => ctx(actor);
  const enable = (id = String(manifest.id)) => executeOperation("plugin.set_project", { id, engagementId: eng.info.id, enabled: true }, ctx());
  return { ws, host, runtime, settings, eng, ctx, enable, close: () => ws.close() };
}

function addHost(eng: ReturnType<Workspace["get"]>, ip: string): string {
  eng.ingest({ format: "penteos-ingest/1", source: { parser: "test@1" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "host", key: { ip }, attributes: { status: "up" } }] } as never, human);
  return eng.query({ kind: "host", text: ip })[0]!.id;
}

const KEY = "SHODAN+SECRET/KEY=12345";

describe("the manifest is checked before anything runs", () => {
  const issues = (contributes: Record<string, unknown>, permissions: string[] = ["graph:read"]) => {
    const r = PluginManifest.safeParse({ ...base, id: "lab.x", permissions, contributes });
    return r.success ? "" : r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(" | ");
  };
  const op = (steps: unknown[], extra: Record<string, unknown> = {}) => ({ operations: [{ name: "go", title: "Go", description: "d", steps, ...extra }] });

  it("hosts outside net:, plain http, a templated host", () => {
    expect(issues(op([{ do: "http", url: "https://evil.test/x" }]), ["net:api.good.test"])).toMatch(/evil.test is not in the plugin's net/);
    // Plain http is fine (internal targets often speak it); net:* takes any url, even a whole one from the input.
    expect(issues(op([{ do: "http", url: "http://api.good.test/x" }]), ["net:api.good.test"])).toBe("");
    expect(issues(op([{ do: "http", url: "{{input.url}}" }], { input: [{ name: "url", type: "url" }] }), ["net:*"])).toBe("");
    expect(issues(op([{ do: "http", url: "ftp://x.test/" }]), ["net:*"])).toMatch(/starts with http/);
    expect(issues(op([{ do: "http", url: "https://{{input.h}}/x" }], { input: [{ name: "h", type: "string" }] }), ["net:api.good.test"])).toMatch(/host written literally/);
    expect(issues(op([{ do: "http", url: "https://eu.api.good.test/x" }]), ["net:*.good.test"])).toBe("");
    // One subdomain per customer: a templated leftmost label, under a wildcard only.
    const site = { input: [{ name: "site", type: "string" }] };
    expect(issues(op([{ do: "http", url: "https://{{input.site}}.atlassian.net/rest" }], site), ["net:*.atlassian.net"])).toBe("");
    expect(issues(op([{ do: "http", url: "https://{{input.site}}.atlassian.net/rest" }], site), ["net:acme.atlassian.net"])).toMatch(/needs a wildcard/);
  });
  it("secrets outside an http step, without permission, in the url path", () => {
    const settings = [{ name: "k", type: "string", secret: true }];
    expect(issues({ settings, ...op([{ do: "set", vars: { x: "{{settings.k}}" } }]) })).toMatch(/settings.k is secret/);
    expect(issues({ settings, ...op([{ do: "http", url: "https://a.test/x" }], { result: "{{settings.k}}" }) }, ["net:a.test"])).toMatch(/settings.k is secret/);
    expect(issues(op([{ do: "http", url: "https://a.test/x", headers: { Authorization: "{{secret:tok}}" } }]), ["net:a.test"])).toMatch(/secrets:tok permission/);
    // A secret webhook path is fine (the audit redacts it); a secret in the host is not.
    expect(issues({ settings, ...op([{ do: "http", url: "https://a.test/{{settings.k}}" }]) }, ["net:a.test"])).toBe("");
    expect(issues({ settings, ...op([{ do: "http", url: "https://{{settings.k}}.a.test/x" }]) }, ["net:*.a.test"])).toMatch(/cannot be part of the host/);
  });
  it("references to things that do not exist, with the exact path", () => {
    const out = issues(op([{ do: "set", vars: { a: "{{input.nope}}" } }, { do: "set", vars: { b: "{{steps.later.x}}" } }, { do: "set", id: "later", vars: { c: "{{item}}" } }]));
    expect(out).toMatch(/operations.0.steps.0.vars: input.nope is not a declared input/);
    expect(out).toMatch(/steps.later does not exist before this point/);
    expect(out).toMatch(/"item" is not available here/);
    expect(issues(op([{ do: "set", vars: { a: "{{input.x | nofilter}}" } }], { input: [{ name: "x", type: "string" }] }))).toMatch(/unknown filter "nofilter"/);
  });
  it("steps that need permissions the plugin did not ask for", () => {
    expect(issues(op([{ do: "notify", title: "x" }]))).toMatch(/needs the notify permission/);
    expect(issues(op([{ do: "finding_draft", title: "x", severity: "low" }]))).toMatch(/findings:draft/);
    expect(issues(op([{ do: "put", type: "nope", attributes: {} }]), ["graph:write"])).toMatch(/not one of this plugin's entity types/);
    expect(issues(op([{ do: "store_query", table: "nope" }]))).toMatch(/no table "nope"/);
  });
  it("menus, providers and tool names", () => {
    expect(issues({ ...op([{ do: "set", vars: { a: 1 } }]), menus: [{ id: "m", title: "M", operation: "go" }] })).toMatch(/ui:menu/);
    expect(issues({ settings: [{ name: "k", type: "string" }], providers: [{ id: "p", label: "P", baseUrl: "https://llm.test/v1", models: ["m"], apiKey: "k" }] }, ["ai:provider", "net:llm.test"])).toMatch(/must be secret/);
    const long = PluginManifest.safeParse({ ...base, id: "lab.a-very-long-plugin-identifier-for-testing", permissions: [], contributes: op([{ do: "set", vars: { a: 1 } }], { name: "an_operation_with_a_long_name" }) });
    expect(long.success).toBe(false);
  });
  it("the reference plugin itself is valid", () => {
    const r = PluginManifest.safeParse(SHODAN);
    expect(r.success ? "" : r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(" | ")).toBe("");
  });
});

describe("templates", () => {
  it("keep types, filter, and never let a secret out of an http request", () => {
    const scope = { input: { n: "5", list: [{ a: 1 }, { a: 2 }] }, settings: { k: new SecretValue("TOPSECRET") } };
    expect(renderValue("{{input.list | pluck:'a'}}", scope)).toEqual([1, 2]);
    expect(renderValue("n={{input.n | int}}", scope)).toBe("n=5");
    expect(renderValue({ x: "{{input.missing | default:'none'}}" }, scope)).toEqual({ x: "none" });
    expect(() => renderValue("{{settings.k}}", scope)).toThrow(TemplateError);
    expect(() => renderValue("Bearer {{settings.k | base64}}", scope)).toThrow(/only be used inside an HTTP request/);
    const used = new Set<string>();
    expect(renderValue("Basic {{settings.k | base64}}", scope, { allowSecrets: true, usedSecrets: used })).toBe(`Basic ${btoa("TOPSECRET")}`);
    expect([...used]).toEqual([btoa("TOPSECRET")]);
    expect(JSON.stringify({ k: new SecretValue("TOPSECRET") })).not.toContain("TOPSECRET");
  });
});

describe("a plugin's operation at work", () => {
  const shodanNet = () =>
    internet({
      "api.shodan.test": (url) => {
        const ip = url.pathname.split("/").pop();
        if (ip === "198.51.100.9") return json({ error: "No information available" }, 404);
        // A careless API echoes the key back: it must never reach the result, the log or the graph.
        return json({ org: "ACME Corp", echo: `key was ${url.searchParams.get("key")}`, data: [{ port: 22, product: "OpenSSH" }, { port: 443 }] });
      },
    });

  it("is a Maestro tool and a form, runs only where enabled, and does what it says", async () => {
    const net = shodanNet();
    const w = await world(SHODAN, net.fetchImpl);
    try {
      const op = getOperation("plugin.lab.shodan.lookup");
      expect(op?.actors).toContain("agent");
      expect(op?.kind).toBe("write");
      expect(op?.description).toMatch(/Sends data to api.shodan.test/);
      await executeOperation("plugin.set_settings", { id: "lab.shodan", values: { apiKey: KEY } }, w.ctx());
      expect(await executeOperation("plugin.settings", { id: "lab.shodan" }, w.ctx())).toMatchObject({ values: {}, secretsSet: ["apiKey"] });

      const hostId = addHost(w.eng, "203.0.113.5");
      await expect(executeOperation("plugin.lab.shodan.lookup", { ip: "203.0.113.5" }, w.ctx())).rejects.toMatchObject({ code: "PLUGIN_UNAVAILABLE" });
      expect(net.calls).toHaveLength(0);
      await w.enable();

      const result = (await executeOperation("plugin.lab.shodan.lookup", { ip: "203.0.113.5" }, w.ctx(agent))) as Record<string, unknown>;
      expect(result).toMatchObject({ ip: "203.0.113.5", org: "ACME Corp", ports: [22, 443] });
      expect(JSON.stringify(result)).not.toContain(KEY);
      expect(new URL(net.calls[0]!.url).searchParams.get("key")).toBe(KEY);

      const banners = w.eng.query({ kind: "lab.shodan:banner" });
      expect(banners.map((b) => b.attributes.port).sort()).toEqual([22, 443]);
      expect(banners[0]!.createdBy).toEqual({ type: "system", id: "plugin:lab.shodan" });
      expect(w.eng.edgesOf(hostId)).toHaveLength(2);
      expect(w.eng.get(hostId)!.ext).toEqual({ "lab.shodan": { org: "ACME Corp", ports: [22, 443] } });

      // The audit chain says what left, to whom, on whose behalf - with the key redacted.
      const egress = w.eng.auditEvents({ limit: 200 }).filter((a) => a.action === "plugin.egress");
      expect(egress).toHaveLength(1);
      expect(egress[0]!.subject).toMatchObject({ plugin: "lab.shodan", host: "api.shodan.test", method: "GET", status: 200, onBehalfOf: agent });
      expect(String((egress[0]!.subject as { url: string }).url)).toContain("key=«secret»");
      expect(JSON.stringify(w.eng.auditEvents({ limit: 500 }))).not.toContain(KEY);
      expect(w.eng.verifyAudit().ok).toBe(true);

      // A business "no" from the plugin is a clear error and does not count against it.
      await expect(executeOperation("plugin.lab.shodan.lookup", { ip: "198.51.100.9" }, w.ctx())).rejects.toMatchObject({ code: "VALIDATION_ERROR", message: expect.stringMatching(/nothing on 198.51.100.9/) });
      expect(w.host.get("lab.shodan")?.health.errors).toBe(0);
    } finally {
      w.close();
    }
  });

  it("refuses to send a local_only project's data anywhere", async () => {
    const net = shodanNet();
    const w = await world(SHODAN, net.fetchImpl);
    try {
      await w.enable();
      w.eng.setInfo({ ...w.eng.info, dataPolicy: "local_only" }, human);
      await expect(executeOperation("plugin.lab.shodan.lookup", { ip: "203.0.113.5" }, w.ctx())).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
      expect(net.calls).toHaveLength(0);
    } finally {
      w.close();
    }
  });

  it("drafts findings but cannot approve them, and its notifications are rate-limited", async () => {
    const w = await world(SHODAN, shodanNet().fetchImpl);
    try {
      await w.enable();
      const hostId = addHost(w.eng, "203.0.113.7");
      const r = (await executeOperation("plugin.lab.shodan.flag", { host: hostId }, w.ctx())) as { id: string; status: string };
      expect(r.status).toBe("draft");
      const finding = w.eng.get(r.id)!;
      expect(finding.attributes).toMatchObject({ status: "draft", title: "SSH exposed to the internet" });
      expect(getOperation("plugin.lab.shodan.flag")?.actors).toEqual(["human"]);

      // The finding triggered the plugin's event handler, which notified once (not in a loop).
      await w.runtime.idle();
      const notes: string[] = [];
      w.eng.events.on("change", (e) => {
        if (e.type === "plugin.notify") notes.push(e.title);
      });
      for (let i = 0; i < 15; i++) await executeOperation("plugin.lab.shodan.ping", { title: `t${i}` }, w.ctx());
      expect(notes.length).toBeLessThanOrEqual(10);
    } finally {
      w.close();
    }
  });
});

describe("a misbehaving plugin ends up off, and the core stays fine", () => {
  const manifest = (url: string, extra: Record<string, unknown> = {}) => ({
    ...base,
    id: "lab.bad",
    name: "Bad plugin",
    permissions: ["net:api.bad.test", "net:*.cdn.bad.test"],
    contributes: { operations: [{ name: "go", title: "Go", description: "d", steps: [{ do: "http", url, ...extra }], timeoutMs: 1500 }] },
  });

  it("a redirect to a host it may not talk to is refused", async () => {
    const net = internet({ "api.bad.test": () => new Response(null, { status: 302, headers: { location: "https://attacker.test/steal" } }) });
    const w = await world(manifest("https://api.bad.test/x"), net.fetchImpl);
    try {
      await w.enable();
      await expect(executeOperation("plugin.lab.bad.go", {}, w.ctx())).rejects.toThrow(/attacker.test: not in the plugin's net/);
      expect(net.calls.map((c) => new URL(c.url).hostname)).toEqual(["api.bad.test"]);
    } finally {
      w.close();
    }
  });

  it("a wildcard covers subdomains only, and redirects within them work", async () => {
    const net = internet({ "api.bad.test": () => new Response(null, { status: 301, headers: { location: "https://eu.cdn.bad.test/y" } }), "eu.cdn.bad.test": () => json({ fine: true }) });
    const w = await world(manifest("https://api.bad.test/x"), net.fetchImpl);
    try {
      await w.enable();
      expect(await executeOperation("plugin.lab.bad.go", {}, w.ctx())).toMatchObject({ body: { fine: true } });
    } finally {
      w.close();
    }
  });

  it("a response bigger than allowed is cut, not loaded", async () => {
    const net = internet({ "api.bad.test": () => new Response("x".repeat(3000), { status: 200 }) });
    const w = await world(manifest("https://api.bad.test/x", { maxBytes: 1024 }), net.fetchImpl);
    try {
      await w.enable();
      await expect(executeOperation("plugin.lab.bad.go", {}, w.ctx())).rejects.toThrow(/more than 1024 bytes/);
    } finally {
      w.close();
    }
  });

  it("an API that hangs times out; one that keeps failing trips the breaker, and its tools disappear", async () => {
    const net = internet({ "api.bad.test": () => json({ boom: true }, 500) });
    const w = await world(manifest("https://api.bad.test/x"), net.fetchImpl);
    try {
      await w.enable();
      for (let i = 0; i < 5; i++) await expect(executeOperation("plugin.lab.bad.go", {}, w.ctx())).rejects.toThrow(/answered 500/);
      await new Promise((r) => setTimeout(r, 20));
      expect(w.host.get("lab.bad")).toMatchObject({ status: "disabled", reason: { code: "TOO_MANY_ERRORS" } });
      expect(getOperation("plugin.lab.bad.go")).toBeUndefined();
      await expect(executeOperation("plugin.lab.bad.go", {}, w.ctx())).rejects.toMatchObject({ code: "UNKNOWN_OPERATION" });
      // The official catalog is untouched.
      expect(getOperation("entity.query")).toBeDefined();
    } finally {
      w.close();
    }
  });

  it("a hanging API is bounded by the step's timeout", async () => {
    const net = internet({ "api.bad.test": (_u, init) => new Promise<Response>((_, reject) => init.signal?.addEventListener("abort", () => reject(new Error("aborted")))) });
    const w = await world(manifest("https://api.bad.test/x", { timeoutMs: 500 }), net.fetchImpl);
    try {
      await w.enable();
      const started = Date.now();
      await expect(executeOperation("plugin.lab.bad.go", {}, w.ctx())).rejects.toThrow(/no answer within 500 ms/);
      expect(Date.now() - started).toBeLessThan(1400);
    } finally {
      w.close();
    }
  });
});

describe("plugin settings", () => {
  it("never return a secret, clear it with an empty value, validate the rest", async () => {
    const manifest = { ...base, id: "lab.cfg", permissions: [], contributes: { settings: [{ name: "token", type: "string", secret: true }, { name: "region", type: "enum", values: ["eu", "us"], default: "eu" }] } };
    const w = await world(manifest, internet({}).fetchImpl);
    try {
      const set = (values: Record<string, unknown>) => executeOperation("plugin.set_settings", { id: "lab.cfg", values }, w.ctx());
      expect(await set({ token: "abcdef123" })).toMatchObject({ secretsSet: ["token"], values: {} });
      await expect(set({ region: "mars" })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
      await expect(set({ other: 1 })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
      expect(await set({ region: "us" })).toMatchObject({ secretsSet: ["token"], values: { region: "us" } });
      expect(readFileSync(join(dataDir, "plugin-data", "lab.cfg", "settings.json"), "utf8")).not.toContain("abcdef123");
      expect(await set({ token: "" })).toMatchObject({ secretsSet: [] });
      const agentCtx = w.ctx(agent);
      await expect(executeOperation("plugin.settings", { id: "lab.cfg" }, agentCtx)).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    } finally {
      w.close();
    }
  });
});
