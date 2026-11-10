import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { codeActivator, declarativeActivator, EgressProxy, executeOperation, type OperationContext, PluginData, PluginHost, PluginRuntime, PluginSettings, pluginTypes, Workspace } from "../src/index.js";

/**
 * Free plugins are watched, not limited: every destination
 * they reach is seen - through the egress proxy or around it - and Penteos warns about what is
 * outside the scope or carries the client's data. Nothing is blocked.
 */

const human: Actor = { type: "human", id: "01J00000000000000000000000" };
let dataDir: string;
let server: Server;
let port: number;
let received: string[];
const lanIp = Object.values(networkInterfaces()).flat().find((i) => i && i.family === "IPv4" && !i.internal)?.address;

beforeEach(async () => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-egress-"));
  received = [];
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += String(d)));
    req.on("end", () => {
      received.push(`${req.method} ${req.url} ${body}`);
      res.end("ok");
    });
  });
  await new Promise<void>((r) => server.listen(0, "0.0.0.0", () => r()));
  port = (server.address() as { port: number }).port;
});
afterEach(async () => {
  pluginTypes.clear();
  server.closeAllConnections();
  await new Promise((r) => server.close(r));
  rmSync(dataDir, { recursive: true, force: true });
});

const CODE = String.raw`
import { spawn } from "node:child_process";
import { connect } from "node:net";
export async function activate(p) {
  p.operation("send", async (input) => {
    const r = await fetch("http://" + input.host + ":" + input.port + "/collect", { method: "POST", body: "user juan.perez@cliente-real.test dni 20.123.456" });
    return { status: r.status, proxied: Boolean(process.env.HTTP_PROXY) };
  });
  // As Python, curl and most tools send plain http through a proxy: the whole request goes to it.
  p.operation("post", async (input) => {
    const proxy = new URL(process.env.HTTP_PROXY);
    const auth = Buffer.from(decodeURIComponent(proxy.username) + ":" + proxy.password).toString("base64");
    const body = "user juan.perez@cliente-real.test";
    const status = await new Promise((resolve, reject) => {
      const s = connect(Number(proxy.port), proxy.hostname, () => s.write("POST http://" + input.host + ":" + input.port + "/collect HTTP/1.1\r\nHost: " + input.host + ":" + input.port + "\r\nProxy-Authorization: Basic " + auth + "\r\nContent-Length: " + body.length + "\r\nConnection: close\r\n\r\n" + body));
      let got = "";
      s.on("data", (d) => (got += d));
      s.on("end", () => resolve(Number(got.split(" ")[1])));
      s.on("error", reject);
    });
    return { status };
  });
  p.operation("direct", async (input) => {
    const s = connect(Number(input.port), input.host);
    await new Promise((r) => s.on("connect", r));
    spawn("sleep", ["1"]);
    await new Promise((r) => setTimeout(r, 900));
    s.destroy();
    return "done";
  });
}
`;

async function world() {
  const dir = join(dataDir, "plugins", "lab.free");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "main.mjs"), CODE);
  const input = [{ name: "host", type: "string", required: true }, { name: "port", type: "integer", required: true }];
  writeFileSync(
    join(dir, "plugin.json"),
    JSON.stringify({
      id: "lab.free",
      name: "Free (lab)",
      version: "1.0.0",
      apiVersion: 1,
      level: "code",
      main: "main.mjs",
      author: { type: "human" },
      permissions: ["net:*"],
      contributes: { operations: ["send", "post", "direct"].map((n) => ({ name: n, title: n, description: n, handler: n, input, timeoutMs: 8000 })) },
    }),
  );
  const ws = new Workspace(join(dataDir, "ws"));
  const data = new PluginData({ dataDir, globalVault: () => ws.vault() });
  const settings = new PluginSettings(dataDir, () => ws.vault());
  const egress = new EgressProxy();
  await egress.start();
  let engagementId = "";
  const runtime = new PluginRuntime({ data, settings, workspace: ws, currentEngagementId: () => engagementId });
  const host = new PluginHost({
    dataDir,
    activationBudgetMs: 15_000,
    activators: {
      declarative: declarativeActivator(data, runtime),
      code: codeActivator(data, runtime, { hostDir: join(dataDir, "plugin-host"), limits: { sampleMs: 200 }, egressEnv: (id) => egress.env(id) }),
    },
  });
  runtime.bind(host);
  data.bind(host);
  egress.onConnection((e) => runtime.egress(e));
  await host.load();
  await host.approve("lab.free", { reviewedCode: true, trust: "free" });
  const eng = ws.create({ clientName: "Lab", name: "Egress", mode: "web", plugins: ["lab.free"] }, human);
  engagementId = eng.info.id;
  const alerts: Array<{ kind: string; text: string }> = [];
  eng.events.on("change", (e) => {
    if (e.type === "plugin.alert") alerts.push({ kind: e.kind, text: e.text });
  });
  const ctx = { workspace: ws, caller: { actor: human, policy: { type: "human" } }, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => { throw new Error("no runner"); }, plugins: host, pluginData: data, pluginRuntime: runtime, pluginSettings: settings } as unknown as OperationContext;
  const call = (op: string, input: Record<string, unknown>) => executeOperation(`plugin.lab.free.${op}`, input, ctx);
  return { eng, runtime, alerts, call, close: () => { runtime.detachCode("lab.free")?.stop(); egress.stop(); ws.close(); } };
}

describe("watching a free plugin", () => {
  it("sees what goes through the proxy, warns about a destination outside the scope and the client's data, and lets it through", async () => {
    const w = await world();
    try {
      // fetch tunnels even http through a proxy: the destination is seen, the body is not.
      const r = (await w.call("send", { host: "127.0.0.1", port })) as { status: number; proxied: boolean };
      expect(r).toEqual({ status: 200, proxied: true });
      expect(received[0]).toContain("juan.perez@cliente-real.test");
      expect(w.alerts.map((a) => a.kind)).toEqual(["destination"]);
      // A plain http request through the proxy (Python, curl…): its body is read too.
      expect(await w.call("post", { host: "127.0.0.1", port })).toEqual({ status: 200 });
      expect(w.alerts.map((a) => a.kind).sort()).toEqual(["client_data", "destination"]);
      expect(w.alerts.find((a) => a.kind === "client_data")?.text).toMatch(/email/);
      expect(w.runtime.activityOf("lab.free").some((a) => a.kind === "egress" && a.where === "elsewhere")).toBe(true);
      expect(w.eng.auditEvents({ limit: 100 }).some((a) => a.action === "plugin.egress_observed")).toBe(true);
      // The same destination again: no new alert for a while.
      await w.call("send", { host: "127.0.0.1", port });
      expect(w.alerts).toHaveLength(2);
    } finally {
      w.close();
    }
  });

  it.skipIf(!lanIp)("sees a connection that goes around the proxy and the programs it starts; inside the scope it does not warn", async () => {
    const w = await world();
    try {
      w.eng.addScopeRule({ effect: "include", target: { type: "ip", value: lanIp! } }, human);
      expect(await w.call("direct", { host: lanIp, port })).toBe("done");
      const activity = w.runtime.activityOf("lab.free");
      expect(activity.some((a) => a.kind === "direct" && a.text === `${lanIp}:${port}` && a.where === "target")).toBe(true);
      expect(activity.some((a) => a.kind === "process" && /sleep 1/.test(a.text))).toBe(true);
      expect(w.alerts).toHaveLength(0);
    } finally {
      w.close();
    }
  });
});
