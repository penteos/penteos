import { spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Actor, INGEST_FORMAT, PluginManifest, ulid } from "@penteos/schema";
import { unzipSync } from "fflate";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  BUNDLED_CATALOG_DIR,
  FindingLibrary,
  codeActivator,
  declarativeActivator,
  executeOperation,
  getOperation,
  type OperationContext,
  outputDir,
  pluginProxyHooks,
  PluginCatalog,
  PluginData,
  PluginHost,
  PluginRuntime,
  PluginSettings,
  pluginTypes,
  Workspace,
} from "../src/index.js";

/**
 * The plugins that ship with Penteos, each end to end against a fake
 * internet that answers like the real service. They are also the contract suite's first members:
 * if a change to the core breaks one of them, this fails.
 */

const human: Actor = { type: "human", id: "01J00000000000000000000000" };
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-bundled-"));
});
afterEach(() => {
  pluginTypes.clear();
  rmSync(dataDir, { recursive: true, force: true });
});

interface Call {
  url: URL;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function internet(routes: Record<string, (call: Call) => Response>) {
  const calls: Call[] = [];
  const fetchImpl = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(String(input));
    const call: Call = { url, method: String(init.method ?? "GET"), headers: Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v])), ...(typeof init.body === "string" ? { body: init.body } : {}) };
    calls.push(call);
    const route = routes[url.hostname] ?? routes["*"];
    if (!route) throw new Error(`fake internet: nothing at ${url.hostname}`);
    return route(call);
  }) as typeof fetch;
  return { fetchImpl, calls };
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

async function world(fetchImpl: typeof fetch, install: string[]) {
  const ws = new Workspace(join(dataDir, "ws"));
  const data = new PluginData({ dataDir, globalVault: () => ws.vault() });
  const settings = new PluginSettings(dataDir, () => ws.vault());
  let ctxFor: (actor: Actor) => OperationContext = () => {
    throw new Error("not ready");
  };
  const runtime = new PluginRuntime({ data, settings, workspace: ws, fetch: fetchImpl, context: (_id, actor) => ctxFor(actor) });
  const host = new PluginHost({ dataDir, activationBudgetMs: 15_000, activators: { declarative: declarativeActivator(data, runtime), code: codeActivator(data, runtime, { hostDir: join(dataDir, "plugin-host") }) } });
  runtime.bind(host);
  data.bind(host);
  await host.load();
  host.bootCompleted();
  const catalog = new PluginCatalog(host);
  for (const id of install) await catalog.install(id, { approve: true });
  const eng = ws.create({ language: "es", clientName: "ACME", name: "Externo", mode: "web", plugins: install }, human);
  const ctx = (actor: Actor = human): OperationContext =>
    ({
      workspace: ws,
      caller: { actor, policy: { type: "human", autonomy: "autonomous", maxRisk: "active" } },
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
  ctxFor = ctx;
  const call = (op: string, input: Record<string, unknown> = {}) => executeOperation(op, input, ctx());
  return { ws, host, runtime, catalog, eng, call, close: () => ws.close() };
}

function addHosts(eng: ReturnType<Workspace["get"]>, ...ips: string[]): Record<string, string> {
  eng.ingest({ format: INGEST_FORMAT, source: { parser: "test@1" }, rawIds: [], observedAt: new Date().toISOString(), items: ips.map((ip) => ({ op: "upsert" as const, kind: "host" as const, key: { ip }, attributes: { status: "up" } })) }, human);
  return Object.fromEntries(ips.map((ip) => [ip, eng.query({ kind: "host", text: ip }).find((h) => h.attributes.ip === ip)!.id]));
}

describe("the catalog", () => {
  it("every bundled plugin is a valid manifest in its own folder, described in both languages", () => {
    const folders = readdirSync(BUNDLED_CATALOG_DIR);
    expect(folders.sort()).toEqual(["penteos.ai-providers", "penteos.excel", "penteos.jira", "penteos.jwt", "penteos.nessus", "penteos.passive-scan", "penteos.shodan", "penteos.slack", "penteos.word-report"]);
    for (const folder of folders) {
      const raw = JSON.parse(readFileSync(join(BUNDLED_CATALOG_DIR, folder, "plugin.json"), "utf8"));
      const r = PluginManifest.safeParse(raw);
      expect(r.success ? "" : `${folder}: ${r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(" | ")}`).toBe("");
      expect(raw.id).toBe(folder);
      expect(raw.description.es && raw.description.en).toBeTruthy();
    }
  });

  it("installs with one approval, says what it sends where, and offers updates", async () => {
    const w = await world(internet({}).fetchImpl, []);
    try {
      const before = w.catalog.list();
      expect(before.map((e) => [e.id, e.sendsTo])).toEqual([
        ["penteos.ai-providers", ["api.deepinfra.com", "api.groq.com", "api.mistral.ai", "openrouter.ai"]],
        ["penteos.excel", []],
        ["penteos.jira", ["*.atlassian.net"]],
        ["penteos.jwt", []],
        ["penteos.nessus", []],
        ["penteos.passive-scan", []],
        ["penteos.shodan", ["api.shodan.io"]],
        ["penteos.slack", ["hooks.slack.com"]],
        ["penteos.word-report", []],
      ]);
      expect(before.every((e) => !e.installed)).toBe(true);
      expect(await w.call("plugin.install", { id: "penteos.jira" })).toMatchObject({ plugin: { status: "active" } });
      expect(w.host.get("penteos.jira")?.status).toBe("active");
      // An older copy installed: the catalog offers the update; updating keeps it approved.
      const installed = join(dataDir, "plugins", "penteos.jira", "plugin.json");
      writeFileSync(installed, readFileSync(installed, "utf8").replace('"version": "1.0.0"', '"version": "0.9.0"'));
      await w.host.rescan();
      expect(w.host.get("penteos.jira")?.status).toBe("modified");
      expect(w.catalog.list().find((e) => e.id === "penteos.jira")).toMatchObject({ installed: { version: "0.9.0" }, update: true });
      await w.catalog.install("penteos.jira", { approve: true });
      expect(w.host.get("penteos.jira")).toMatchObject({ status: "active", version: "1.0.0" });
      expect(readdirSync(join(dataDir, "plugins"))).toEqual(["penteos.jira"]);
    } finally {
      w.close();
    }
  });
});

describe("Shodan", () => {
  const KEY = "SHODAN+KEY/abc123";
  const shodan = () =>
    internet({
      "api.shodan.io": (c) => {
        const ip = c.url.pathname.split("/").pop();
        if (ip === "198.51.100.77") return json({ error: "No information available for that IP." }, 404);
        return json({
          ip_str: ip,
          org: "ACME Hosting",
          isp: "ACME ISP",
          asn: "AS64500",
          os: null,
          country_name: "Argentina",
          ports: [443, 22],
          vulns: ["CVE-2023-38408"],
          hostnames: ["www.acme.test"],
          last_update: "2026-10-30T11:22:33.000000",
          debug: `key=${c.url.searchParams.get("key")}`,
          data: [
            { port: 22, transport: "tcp", product: "OpenSSH", version: "8.9p1", data: "SSH-2.0-OpenSSH_8.9p1", timestamp: "2026-10-30T11:22:33", _shodan: { module: "ssh" } },
            { port: 443, transport: "tcp", product: "nginx", data: "HTTP/1.1 200 OK", timestamp: "2026-10-29T08:00:00", _shodan: { module: "https" } },
          ],
        });
      },
    });

  it("asks for its key before calling anyone, and refuses private addresses", async () => {
    const net = shodan();
    const w = await world(net.fetchImpl, ["penteos.shodan"]);
    try {
      await expect(w.call("plugin.penteos.shodan.lookup", { ip: "203.0.113.10" })).rejects.toThrow(/set up apiKey/);
      await w.call("plugin.set_settings", { id: "penteos.shodan", values: { apiKey: KEY } });
      await expect(w.call("plugin.penteos.shodan.lookup", { ip: "10.0.0.5" })).rejects.toThrow(/private address/);
      await expect(w.call("plugin.penteos.shodan.lookup", { ip: "198.51.100.77" })).rejects.toThrow(/no information about 198.51.100.77/);
      expect(net.calls).toHaveLength(1);
      expect(w.host.get("penteos.shodan")?.health.errors).toBe(0);
    } finally {
      w.close();
    }
  });

  it("records banners on the exact host, annotates it, and never shows its key", async () => {
    const net = shodan();
    const w = await world(net.fetchImpl, ["penteos.shodan"]);
    try {
      await w.call("plugin.set_settings", { id: "penteos.shodan", values: { apiKey: KEY } });
      const ids = addHosts(w.eng, "203.0.113.10", "203.0.113.100");
      const result = (await w.call("plugin.penteos.shodan.lookup", { ip: "203.0.113.10" })) as Record<string, unknown>;
      expect(result).toMatchObject({ ip: "203.0.113.10", org: "ACME Hosting", ports: [22, 443], vulns: ["CVE-2023-38408"], banners: 2, onHost: true });
      expect(net.calls[0]!.url.searchParams.get("key")).toBe(KEY);
      expect(JSON.stringify(result)).not.toContain("abc123");

      const banners = w.eng.query({ kind: "penteos.shodan:banner" });
      expect(banners.map((b) => `${b.attributes.port}/${b.attributes.product}/${b.attributes.module}`).sort()).toEqual(["22/OpenSSH/ssh", "443/nginx/https"]);
      expect(w.eng.edgesOf(ids["203.0.113.10"]!)).toHaveLength(2);
      expect(w.eng.edgesOf(ids["203.0.113.100"]!)).toHaveLength(0);
      expect(w.eng.get(ids["203.0.113.10"]!)!.ext?.["penteos.shodan"]).toMatchObject({ org: "ACME Hosting", vulns: ["CVE-2023-38408"], country: "Argentina" });
      expect(w.eng.get(ids["203.0.113.10"]!)!.ext?.["penteos.shodan"]).not.toHaveProperty("os");
      expect(JSON.stringify(w.eng.auditEvents({ limit: 500 }))).not.toContain("abc123");

      // Again: the same banners are updated, not duplicated.
      await w.call("plugin.penteos.shodan.lookup", { ip: "203.0.113.10" });
      expect(w.eng.query({ kind: "penteos.shodan:banner" })).toHaveLength(2);
    } finally {
      w.close();
    }
  });

  it("looks up new public hosts on its own only when told to", async () => {
    const net = shodan();
    const w = await world(net.fetchImpl, ["penteos.shodan"]);
    try {
      await w.call("plugin.set_settings", { id: "penteos.shodan", values: { apiKey: KEY } });
      addHosts(w.eng, "203.0.113.20");
      await w.runtime.idle();
      expect(net.calls).toHaveLength(0);
      await w.call("plugin.set_settings", { id: "penteos.shodan", values: { autoLookup: true } });
      addHosts(w.eng, "203.0.113.21", "10.1.1.1");
      await w.runtime.idle();
      expect(net.calls.map((c) => c.url.pathname)).toEqual(["/shodan/host/203.0.113.21"]);
    } finally {
      w.close();
    }
  });
});

describe("Jira", () => {
  const jira = () =>
    internet({
      "*": (c) => {
        if (!c.url.hostname.endsWith(".atlassian.net")) throw new Error(`unexpected ${c.url.hostname}`);
        const n = 100 + Math.floor(Math.random() * 900);
        return json({ id: String(n), key: `SEC-${n}`, self: `https://${c.url.hostname}/rest/api/2/issue/${n}` }, 201);
      },
    });

  it("creates the issue with Basic auth, notes it on the finding, and does not export twice by accident", async () => {
    const net = jira();
    const w = await world(net.fetchImpl, ["penteos.jira"]);
    try {
      await w.call("plugin.set_settings", { id: "penteos.jira", values: { site: "acme", email: "ana@acme.test", apiToken: "ATATT-secret-token", projectKey: "SEC" } });
      const f = (await w.call("finding.create", { title: "IDOR en /api/users/{id}", severity: "high", description: "Se leen usuarios ajenos.", impact: "Exposición de datos.", remediation: "Validar el dueño del recurso." })) as { id: string };
      const out = (await w.call("plugin.penteos.jira.export_finding", { findingId: f.id })) as { issueKey: string; issueUrl: string };
      expect(out.issueKey).toMatch(/^SEC-\d+$/);
      expect(out.issueUrl).toBe(`https://acme.atlassian.net/browse/${out.issueKey}`);
      const sent = net.calls[0]!;
      expect(sent.url.toString()).toBe("https://acme.atlassian.net/rest/api/2/issue");
      expect(sent.headers.authorization).toBe(`Basic ${Buffer.from("ana@acme.test:ATATT-secret-token").toString("base64")}`);
      const body = JSON.parse(sent.body!) as { fields: Record<string, unknown> };
      expect(body.fields).toMatchObject({ project: { key: "SEC" }, summary: "[HIGH] IDOR en /api/users/{id}", issuetype: { name: "Bug" }, labels: ["penteos", "high"] });
      expect(String(body.fields.description)).toContain("h3. Descripción\nSe leen usuarios ajenos.");
      expect(w.eng.get(f.id)!.ext?.["penteos.jira"]).toEqual({ issueKey: out.issueKey, issueUrl: out.issueUrl });
      expect(JSON.stringify(w.eng.auditEvents({ limit: 500 }))).not.toContain("ATATT-secret-token");

      await expect(w.call("plugin.penteos.jira.export_finding", { findingId: f.id })).rejects.toThrow(/Already exported as SEC-/);
      await w.call("plugin.penteos.jira.export_finding", { findingId: f.id, again: true });
      expect(net.calls).toHaveLength(2);
      // Exporting a deliverable to a third party is a person's decision: not a Maestro tool.
      expect(getOperation("plugin.penteos.jira.export_finding")?.actors).toEqual(["human"]);
    } finally {
      w.close();
    }
  });

  it("a site setting that tries to point elsewhere is refused at the door", async () => {
    const net = jira();
    const w = await world(net.fetchImpl, ["penteos.jira"]);
    try {
      await w.call("plugin.set_settings", { id: "penteos.jira", values: { site: "evil.test/x#", email: "a@b.test", apiToken: "tok-12345", projectKey: "SEC" } });
      const f = (await w.call("finding.create", { title: "X", severity: "low" })) as { id: string };
      await expect(w.call("plugin.penteos.jira.export_finding", { findingId: f.id })).rejects.toThrow(/evil.test: not in the plugin's net/);
      expect(net.calls).toHaveLength(0);
    } finally {
      w.close();
    }
  });
});

describe("Slack", () => {
  const HOOK = "https://hooks.slack.com/services/T000/B000/XXXXSECRET";
  const slack = () => internet({ "hooks.slack.com": () => new Response("ok", { status: 200, headers: { "content-type": "text/plain" } }) });

  it("posts serious findings on its own, the rest only by hand, and keeps the webhook out of the audit", async () => {
    const net = slack();
    const w = await world(net.fetchImpl, ["penteos.slack"]);
    try {
      await w.call("plugin.set_settings", { id: "penteos.slack", values: { webhook: HOOK } });
      await w.call("finding.create", { title: "RCE en el panel", severity: "critical" });
      await w.call("finding.create", { title: "Cabeceras ausentes", severity: "low" });
      await w.runtime.idle();
      expect(net.calls).toHaveLength(1);
      expect(net.calls[0]!.url.toString()).toBe(HOOK);
      expect(JSON.parse(net.calls[0]!.body!).text).toContain("*[CRITICAL] RCE en el panel*\nACME · Externo");

      const low = w.eng.query({ kind: "finding", text: "Cabeceras" })[0]!;
      await w.call("plugin.penteos.slack.notify_finding", { findingId: low.id });
      await w.call("plugin.penteos.slack.post", { text: "Arrancamos la fase de explotación" });
      expect(net.calls).toHaveLength(3);
      const audit = JSON.stringify(w.eng.auditEvents({ limit: 500 }));
      expect(audit).not.toContain("XXXXSECRET");
      expect(audit).toContain("plugin.egress");
    } finally {
      w.close();
    }
  });
});

describe("AI providers", () => {
  it("offers DeepInfra, Groq, OpenRouter and Mistral, each with its own key", async () => {
    const w = await world(internet({}).fetchImpl, ["penteos.ai-providers"]);
    try {
      await w.call("plugin.set_settings", { id: "penteos.ai-providers", values: { deepinfraKey: "di-key-123" } });
      const providers = w.runtime.providers("es");
      expect(providers.map((p) => [p.key, p.baseUrl, Boolean(p.apiKey)])).toEqual([
        ["plugin:penteos.ai-providers:deepinfra", "https://api.deepinfra.com/v1/openai", true],
        ["plugin:penteos.ai-providers:groq", "https://api.groq.com/openai/v1", false],
        ["plugin:penteos.ai-providers:openrouter", "https://openrouter.ai/api/v1", false],
        ["plugin:penteos.ai-providers:mistral", "https://api.mistral.ai/v1", false],
      ]);
      expect(providers[0]!.apiKey).toBe("di-key-123");
    } finally {
      w.close();
    }
  });
});

describe("Nessus", () => {
  const NESSUS = `<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy><policyName>Basic Network Scan</policyName></Policy>
<Report name="lab">
<ReportHost name="203.0.113.10"><HostProperties>
<tag name="host-ip">203.0.113.10</tag><tag name="host-fqdn">www.acme.test</tag>
<tag name="operating-system">Linux Kernel 5.15 on Ubuntu 22.04</tag><tag name="nessus-version">10.7.1</tag>
</HostProperties>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information"><description>info</description></ReportItem>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2" pluginID="70658" pluginName="SSH Server CBC Mode Ciphers Enabled">
<synopsis>The SSH server is configured to use Cipher Block Chaining.</synopsis><description>CBC &amp; friends &lt;weak&gt;</description>
<solution>Disable CBC mode ciphers.</solution><cvss3_base_score>5.3</cvss3_base_score><plugin_output>aes128-cbc</plugin_output></ReportItem>
<ReportItem port="443" svc_name="www" protocol="tcp" severity="4" pluginID="111111" pluginName="Apache 2.4.x &lt; 2.4.58 Multiple Vulnerabilities">
<description>Outdated.</description><cve>CVE-2023-45802</cve><cve>CVE-2023-43622</cve><solution>Upgrade.</solution></ReportItem>
<ReportItem port="161" svc_name="snmp" protocol="udp" severity="3" pluginID="41028" pluginName="SNMP Agent Default Community Name (public)"><description>public</description></ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="1" pluginID="10114" pluginName="ICMP Timestamp Request Remote Date Disclosure"><description>icmp</description></ReportItem>
</ReportHost>
<ReportHost name="203.0.113.11"><HostProperties><tag name="host-ip">203.0.113.11</tag></HostProperties>
<ReportItem port="80" svc_name="www" protocol="tcp" severity="0" pluginID="10107" pluginName="HTTP Server Type and Version"></ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>`;
  const b64 = Buffer.from(NESSUS).toString("base64");

  it("imports hosts, services and vulnerabilities as observations, only where the plugin is enabled", async () => {
    const w = await world(internet({}).fetchImpl, ["penteos.nessus"]);
    try {
      expect(w.host.get("penteos.nessus")?.status).toBe("active");
      const r = (await w.call("ingest.import", { filename: "scan.nessus", contentBase64: b64 })) as { format: string; summary: { created: Record<string, number> } };
      expect(r.format).toBe("penteos.nessus:nessus");
      expect(r.summary.created).toMatchObject({ host: 2, domain: 1, service: 4 });
      const hosts = w.eng.query({ kind: "host" });
      expect(hosts.find((h) => h.attributes.ip === "203.0.113.10")?.attributes).toMatchObject({ hostnames: ["www.acme.test"], os: { name: "Linux Kernel 5.15 on Ubuntu 22.04" } });
      const services = w.eng.query({ kind: "service" }).map((x) => `${x.attributes.transport}/${x.attributes.port}/${x.attributes.protocol ?? ""}`).sort();
      expect(services).toEqual(["tcp/22/ssh", "tcp/443/http", "tcp/80/http", "udp/161/snmp"]);
      const obs = w.eng.query({ kind: "observation" }).map((o) => o.attributes);
      expect(obs.map((o) => `${o.severityHint} ${o.sourceRule}`).sort()).toEqual(["critical nessus:111111", "high nessus:41028", "low nessus:10114", "medium nessus:70658"]);
      const apache = obs.find((o) => o.sourceRule === "nessus:111111")!;
      expect(apache.title).toBe("Apache 2.4.x < 2.4.58 Multiple Vulnerabilities");
      expect(String(apache.detail)).toContain("CVE: CVE-2023-45802, CVE-2023-43622");
      expect(String(obs.find((o) => o.sourceRule === "nessus:70658")!.detail)).toContain("CBC & friends <weak>");
      expect((apache.affects as Array<{ kind: string }>)[0]!.kind).toBe("service");
      expect((obs.find((o) => o.sourceRule === "nessus:10114")!.affects as Array<{ kind: string }>)[0]!.kind).toBe("host");

      // Not enabled in a project: the format is not recognized there.
      w.eng.setInfo({ ...w.eng.info, plugins: [] }, { type: "human", id: "01J00000000000000000000000" });
      await expect(w.call("ingest.import", { filename: "scan.nessus", contentBase64: b64 })).rejects.toThrow(/unrecognized file/);
    } finally {
      for (const p of w.host.list()) (w.runtime as unknown as { detachCode(id: string): { stop(): void } | undefined }).detachCode(p.id)?.stop();
      w.close();
    }
  });
});

describe("JWT inspector", () => {
  const sign = (header: object, payload: object, secret: string) => {
    const b = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const h = b(header);
    const p = b(payload);
    return `${h}.${p}.${createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url")}`;
  };

  it("cracks a weak secret, flags what to test, is a Maestro tool, and brings its templates", async () => {
    const w = await world(internet({}).fetchImpl, ["penteos.jwt"]);
    try {
      const token = sign({ alg: "HS256", kid: "../../dev/null" }, { sub: "42", role: "user", exp: Math.floor(Date.now() / 1000) + 3600 }, "acme-2026");
      const weakNotListed = (await w.call("plugin.penteos.jwt.inspect", { token })) as { secret?: string; issues: Array<{ title: string }> };
      expect(weakNotListed.secret).toBeUndefined();
      const r = (await w.call("plugin.penteos.jwt.inspect", { token, words: "acme\nacme-2026" })) as { secret?: string; issues: Array<{ title: string; template?: string }> };
      expect(r.secret).toBe("acme-2026");
      expect(r.issues.map((i) => i.title)).toEqual(expect.arrayContaining(["Weak HMAC secret", "kid header", "Authorization claims"]));
      expect(r.issues.some((i) => i.title === "No expiry (exp)")).toBe(false);
      const none = (await w.call("plugin.penteos.jwt.inspect", { token: `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from('{"sub":"1"}').toString("base64url")}.` })) as { issues: Array<{ template?: string }> };
      expect(none.issues.map((i) => i.template)).toContain("jwt-alg-none");
      await expect(w.call("plugin.penteos.jwt.inspect", { token: "not-a-jwt" })).rejects.toThrow(/3 parts/);
      expect(getOperation("plugin.penteos.jwt.inspect")?.actors).toContain("agent");

      const library = new FindingLibrary();
      library.usePluginTemplates(() => w.runtime.templates());
      expect(library.list("jwt").map((t) => `${t.id}:${t.source}`).sort()).toEqual(["jwt-alg-none:plugin", "jwt-no-expiry:plugin", "jwt-weak-hmac-secret:plugin"]);
      expect(library.get("jwt-weak-hmac-secret")?.severity).toBe("high");
    } finally {
      for (const p of w.host.list()) (w.runtime as unknown as { detachCode(id: string): { stop(): void } | undefined }).detachCode(p.id)?.stop();
      w.close();
    }
  });
});

function seedFindings(eng: ReturnType<Workspace["get"]>): void {
  const h = eng.createEntity("host", { ip: "10.0.0.7", networkContext: "default" }, human);
  eng.createEntity("finding", { title: "SQL injection in login", severity: "critical", status: "approved", description: "The login form builds its query by hand.", impact: "Full database read.", remediation: "Use parameters.", instances: [{ id: ulid(), entity: { id: h.id, kind: "host" }, status: "open", location: "/login" }] }, human);
  eng.createEntity("finding", { title: "Verbose banner", severity: "low", status: "approved", description: "nginx/1.18.0" }, human);
  eng.createEntity("finding", { title: "Unreviewed lead", severity: "high", status: "draft" }, human);
}

const docXml = (file: string) => new TextDecoder().decode(unzipSync(new Uint8Array(readFileSync(file)))["word/document.xml"]!);

describe("Custom Word report", () => {
  it("signs the official document as asked: executive or technical, from a severity, with the auditor's notes", async () => {
    const w = await world(internet({}).fetchImpl, ["penteos.word-report"]);
    try {
      seedFindings(w.eng);
      const r = (await w.call("plugin.run", { name: "plugin.penteos.word-report.generate", input: { author: "Juan Pérez", company: "Auditores SA", minSeverity: "medium", technical: false, notes: "Se probó solo la aplicación web.", file: "acme-ejecutivo" } })) as { result: { name: string } };
      expect(r.result.name).toBe("acme-ejecutivo.docx");
      const xml = docXml(join(outputDir(w.eng.dir, "penteos.word-report"), "acme-ejecutivo.docx"));
      for (const s of ["Juan Pérez", "Auditores SA", "Notas del auditor", "Se probó solo la aplicación web.", "SQL injection in login"]) expect(xml).toContain(s);
      expect(xml).not.toContain("Verbose banner");
      expect(xml).not.toContain("Hallazgos detallados");
      expect(xml).not.toContain("Unreviewed lead");
      // No notes: no empty section.
      await w.call("plugin.run", { name: "plugin.penteos.word-report.generate", input: { author: "Ana", file: "tecnico" } });
      const tech = docXml(join(outputDir(w.eng.dir, "penteos.word-report"), "tecnico.docx"));
      expect(tech).toContain("Hallazgos detallados");
      expect(tech).not.toContain("Notas del auditor");
      // It is offered next to Word and Markdown in the Deliverable panel.
      expect(w.runtime.catalog().find((p) => p.id === "penteos.word-report")?.exports.map((x) => x.operation)).toEqual(["generate"]);
    } finally {
      w.close();
    }
  });
});

describe("Passive scanner", () => {
  const res = (url: string, status: number, headers: Array<[string, string]>, body: string) => ({
    req: { method: "GET", url: new URL(url), headers: [["Host", new URL(url).host]] as Array<[string, string]>, body: Buffer.alloc(0) },
    res: { status, statusText: "OK", headers, body: Buffer.from(body) },
  });

  it("drafts each problem a response shows, once, without touching the response", async () => {
    const w = await world(internet({}).fetchImpl, ["penteos.passive-scan"]);
    try {
      const hooks = pluginProxyHooks(w.runtime);
      // A fake key, split so secret scanners don't flag the fixture itself.
      const awsKey = "AKIA" + "ABCDEFGHIJKLMNOP";
      const page = res("https://shop.acme.test/account", 200, [["Content-Type", "text/html; charset=utf-8"], ["Set-Cookie", "PHPSESSID=abc123; path=/"]], `<html><script>var k='${awsKey}';</script></html>`);
      const error = res("https://shop.acme.test/search?q=x", 500, [["Content-Type", "text/html"]], "<b>Warning</b>: You have an error in your SQL syntax; check the manual near 'x' at line 1");
      const listing = res("https://files.acme.test/backup/", 200, [["Content-Type", "text/html"], ["Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"], ["X-Content-Type-Options", "nosniff"], ["Strict-Transport-Security", "max-age=31536000"]], "<html><title>Index of /backup</title></html>");
      for (const m of [page, error, listing, page, error]) {
        const out = await hooks.response!(w.eng, m.req, m.res, { source: "test" });
        expect(out?.res).toBe(m.res);
      }
      for (let i = 0; i < 100 && w.eng.query({ kind: "finding", limit: 20 }).length < 5; i++) await new Promise((r) => setTimeout(r, 30));
      await new Promise((r) => setTimeout(r, 200));
      const titles = w.eng.query({ kind: "finding", limit: 20 }).map((f) => [f.attributes.title, f.attributes.severity, f.attributes.status]).sort();
      expect(titles).toEqual([
        ["AWS access key expuesta en shop.acme.test", "high", "draft"],
        ["Cookie de sesión PHPSESSID sin protección en shop.acme.test", "low", "draft"],
        ["Faltan cabeceras de seguridad en shop.acme.test", "low", "draft"],
        ["Listado de directorio habilitado en files.acme.test", "low", "draft"],
        ["SQL error con detalle técnico en shop.acme.test", "medium", "draft"],
      ]);
      // The key is never written whole.
      expect(JSON.stringify(w.eng.query({ kind: "finding", limit: 20 }).map((f) => f.attributes))).not.toContain(awsKey);
      const summary = (await w.call("plugin.run", { name: "plugin.penteos.passive-scan.summary", input: {} })) as { result: { items: unknown[] } };
      expect(summary.result.items).toHaveLength(5);
      await w.call("plugin.run", { name: "plugin.penteos.passive-scan.forget", input: {} });
      expect(((await w.call("plugin.run", { name: "plugin.penteos.passive-scan.summary", input: {} })) as { result: { items: unknown[] } }).result.items).toHaveLength(0);
      // It teaches the Maestro how to work with it.
      expect(w.runtime.skillsFor(w.eng).map((s) => s.title)).toEqual(["Escáner pasivo"]);
    } finally {
      for (const p of w.host.list()) w.runtime.detachCode(p.id)?.stop();
      w.close();
    }
  });
});

describe("Findings to Excel", () => {
  it.skipIf(spawnSync("python3", ["--version"]).status !== 0)("writes a real .xlsx of the deliverable's findings, in Python with no libraries", async () => {
    const w = await world(internet({}).fetchImpl, ["penteos.excel"]);
    try {
      seedFindings(w.eng);
      const r = (await w.call("plugin.run", { name: "plugin.penteos.excel.excel", input: {} })) as { result: { name: string; findings: number } };
      expect(r.result).toMatchObject({ name: "hallazgos-acme.xlsx", findings: 2 });
      const zip = unzipSync(new Uint8Array(readFileSync(join(outputDir(w.eng.dir, "penteos.excel"), "hallazgos-acme.xlsx"))));
      expect(Object.keys(zip).sort()).toEqual(["[Content_Types].xml", "_rels/.rels", "xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/workbook.xml", "xl/worksheets/sheet1.xml"]);
      const sheet = new TextDecoder().decode(zip["xl/worksheets/sheet1.xml"]!);
      for (const s of ["Hallazgo", "SQL injection in login", "Crítica", "10.0.0.7 (/login)", "Use parameters.", 'state="frozen"', "autoFilter"]) expect(sheet).toContain(s);
      expect(sheet).not.toContain("Unreviewed lead");
      expect(sheet.indexOf("SQL injection in login")).toBeLessThan(sheet.indexOf("Verbose banner"));
    } finally {
      for (const p of w.host.list()) w.runtime.detachCode(p.id)?.stop();
      w.close();
    }
  });
});
