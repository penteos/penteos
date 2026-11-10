import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttp, request as httpRequest, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Actor, PluginManifest } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CertificateAuthority,
  codeActivator,
  composeProxyHooks,
  declarativeActivator,
  DEFAULT_PROXY_SETTINGS,
  type Engagement,
  Interceptor,
  type OperationContext,
  PenteosProxy,
  PluginData,
  PluginHost,
  PluginRuntime,
  PluginSettings,
  pluginProxyHooks,
  pluginTypes,
  Workspace,
} from "../src/index.js";

/**
 * Plugins in the proxy's path: a passive scanner that sees
 * responses aside, hooks that change requests and responses before the operator's interception,
 * and traffic that never waits on a slow or broken plugin.
 */

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let proxy: PenteosProxy;
let target: Server;
let port = 0;
let runtime: PluginRuntime;
let host: PluginHost;
let seen: { url?: string; headers?: Record<string, unknown> } = {};

const CODE = String.raw`
export async function activate(p) {
  p.operation("tag", async (req) => {
    const headers = [...req.headers, ["X-Seen-By", "lab.proxy"]];
    return req.url.endsWith("/old") ? { headers, url: req.url.replace("/old", "/new") } : { headers };
  });
  p.operation("stamp", async (res) => ({ body: res.body + " (checked)" }));
  p.operation("scan", async (res, penteos) => {
    if (/password=/.test(res.body ?? "")) await penteos.findingDraft({ title: "Password in a response", severity: "medium", description: res.request.url });
  });
  p.operation("slow", async () => { await new Promise((r) => setTimeout(r, 3000)); return { body: "too late" }; });
  p.operation("boom", async () => { throw new Error("broken hook"); });
}
`;

const MANIFEST = {
  id: "lab.proxy",
  name: "Proxy (lab)",
  version: "1.0.0",
  apiVersion: 1,
  level: "code",
  main: "main.mjs",
  author: { type: "human", name: "Lab" },
  permissions: ["proxy", "findings:draft"],
  contributes: {
    proxy: [
      { id: "tag", on: "request", handler: "tag", modify: true, hosts: ["127.0.0.1"] },
      { id: "stamp", on: "response", handler: "stamp", modify: true, contentTypes: ["text/plain"], path: "^/(new|plain)" },
      { id: "scan", on: "response", handler: "scan" },
      { id: "slow", on: "response", handler: "slow", modify: true, path: "^/slow", timeoutMs: 300 },
      { id: "boom", on: "response", handler: "boom", modify: true, path: "^/boom" },
    ],
  },
};

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-plugin-proxy-"));
  const pdir = join(dir, "plugins", "lab.proxy");
  mkdirSync(pdir, { recursive: true });
  writeFileSync(join(pdir, "plugin.json"), JSON.stringify(MANIFEST));
  writeFileSync(join(pdir, "main.mjs"), CODE);
  ws = new Workspace(join(dir, "data"));
  const data = new PluginData({ dataDir: dir, globalVault: () => ws.vault() });
  const settings = new PluginSettings(dir, () => ws.vault());
  const ctxFor = (engagementId: string, actor: Actor) => ({ workspace: ws, caller: { actor, policy: { type: "human" } }, defaultEngagementId: engagementId, engagement: () => ws.get(engagementId), runner: () => { throw new Error("no runner"); }, plugins: host, pluginData: data, pluginRuntime: runtime, pluginSettings: settings }) as unknown as OperationContext;
  runtime = new PluginRuntime({ data, settings, workspace: ws, context: ctxFor });
  host = new PluginHost({ dataDir: dir, activationBudgetMs: 15_000, activators: { declarative: declarativeActivator(data, runtime), code: codeActivator(data, runtime, { hostDir: join(dir, "plugin-host"), limits: { sampleMs: 300 } }) } });
  runtime.bind(host);
  data.bind(host);
  await host.load();
  await host.approve("lab.proxy", { reviewedCode: true, trust: "isolated" });
  expect(host.get("lab.proxy")?.status).toBe("active");
  eng = ws.create({ clientName: "Lab", name: "Proxy hooks", mode: "web", plugins: ["lab.proxy"] }, human);

  target = createHttp((req, res) => {
    seen = { url: req.url, headers: req.headers };
    req.resume();
    req.on("end", () => {
      if (req.url === "/secret") {
        res.writeHead(200, { "Content-Type": "text/html" });
        return res.end("<form>password=hunter2</form>");
      }
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
  });
  await new Promise<void>((r) => target.listen(0, "127.0.0.1", () => r()));
  port = (target.address() as { port: number }).port;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, human);
  const ca = await CertificateAuthority.load(join(dir, "ca"));
  const interceptor = new Interceptor();
  proxy = new PenteosProxy(ws, ca, { token: "t", actor: human, settings: () => DEFAULT_PROXY_SETTINGS });
  proxy.hooks = composeProxyHooks(pluginProxyHooks(runtime), { request: (e, req) => interceptor.onRequest(e, req), response: (e, req, res) => interceptor.onResponse(e, req, res) });
  await proxy.start(0);
});

afterEach(async () => {
  runtime.detachCode("lab.proxy")?.stop();
  await proxy.close();
  target.close();
  ws.close();
  pluginTypes.clear();
  rmSync(dir, { recursive: true, force: true });
});

function send(path: string): Promise<{ status: number; body: string; ms: number }> {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port: proxy.port, method: "GET", path: `http://127.0.0.1:${port}${path}`, headers: { "Proxy-Authorization": `Basic ${Buffer.from(`${eng.info.id}:t`).toString("base64")}`, Host: `127.0.0.1:${port}` } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString(), ms: Date.now() - started }));
      },
    );
    r.on("error", reject);
    r.end();
  });
}

describe("plugin proxy hooks", () => {
  it("change requests and responses that match, scope still applies", async () => {
    const r = await send("/old");
    expect(seen.url).toBe("/new");
    expect(seen.headers?.["x-seen-by"]).toBe("lab.proxy");
    expect(r).toMatchObject({ status: 200, body: "ok (checked)" });
    // A path the response hook does not match: unchanged.
    expect((await send("/other")).body).toBe("ok");
  });

  it("a viewing hook works aside: a passive scanner drafts a finding without holding the response", async () => {
    const r = await send("/secret");
    expect(r.body).toContain("password=hunter2");
    for (let i = 0; i < 50 && !eng.query({ kind: "finding", limit: 10 }).length; i++) await new Promise((x) => setTimeout(x, 40));
    const f = eng.query({ kind: "finding", limit: 10 });
    expect(f.map((x) => [x.attributes.title, x.attributes.status])).toEqual([["Password in a response", "draft"]]);
  });

  it("a slow or broken hook never holds or breaks the traffic", async () => {
    const slow = await send("/slow");
    expect(slow.body).toBe("ok");
    expect(slow.ms).toBeLessThan(2500);
    expect((await send("/boom")).body).toBe("ok");
    expect(host.logOf("lab.proxy").join("\n")).toMatch(/proxy hook boom: .*broken hook/);
    expect(host.logOf("lab.proxy").join("\n")).toMatch(/proxy hook slow: no answer within 300 ms/);
  });

  it("only in projects where the plugin is enabled", async () => {
    eng.setInfo({ ...eng.info, plugins: [] }, human);
    await send("/old");
    expect(seen.url).toBe("/old");
    expect(seen.headers?.["x-seen-by"]).toBeUndefined();
  });

  it("need the proxy permission and code", () => {
    const noPerm = PluginManifest.safeParse({ ...MANIFEST, permissions: ["findings:draft"] });
    expect(JSON.stringify(noPerm.error?.issues)).toMatch(/proxy permission/);
    const bad = PluginManifest.safeParse({ ...MANIFEST, contributes: { proxy: [{ id: "x", on: "request", handler: "tag", path: "([" }] } });
    expect(JSON.stringify(bad.error?.issues)).toMatch(/regular expression/);
  });
});
