import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttp, request as httpRequest, type Server } from "node:http";
import { createServer as createHttps } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect as tlsConnect } from "node:tls";
import { gzipSync } from "node:zlib";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PenteosProxy, CertificateAuthority, DEFAULT_PROXY_SETTINGS, type Engagement, type ProxySettings, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let ca: CertificateAuthority;
let proxy: PenteosProxy;
let settings: ProxySettings;
const servers: Server[] = [];
let httpPort = 0;
let httpsPort = 0;
let outPort = 0;

function listen(s: Server): Promise<number> {
  servers.push(s);
  return new Promise((r) => s.listen(0, "127.0.0.1", () => r((s.address() as { port: number }).port)));
}

const handler = (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    if (req.url === "/gz") {
      res.writeHead(200, { "Content-Type": "text/html", "Content-Encoding": "gzip", Server: "nginx/1.25" });
      return res.end(gzipSync("<h1>comprimido</h1>"));
    }
    res.writeHead(200, { "Content-Type": "text/plain", "Set-Cookie": "sid=abc" });
    res.end(`${req.method} ${req.url} body=${body}`);
  });
};

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-proxy-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Proxy", mode: "web" }, human);
  ca = await CertificateAuthority.load(join(dir, "data", "config"));
  httpPort = await listen(createHttp(handler));
  httpsPort = await listen(createHttps(await ca.pemFor("127.0.0.1"), handler) as unknown as Server);
  outPort = await listen(createHttp(handler)); // a server that is NOT in scope
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: `${httpPort},${httpsPort}` }, human);
  settings = { ...DEFAULT_PROXY_SETTINGS };
  proxy = new PenteosProxy(ws, ca, { token: "t0k", actor: human, settings: () => settings });
  await proxy.start(0);
});

afterEach(async () => {
  await proxy?.close();
  for (const s of servers.splice(0)) s.close();
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const auth = (user = eng.info.id) => `Basic ${Buffer.from(`${user}:t0k`).toString("base64")}`;

/** A plain-HTTP request through the proxy (absolute URL in the request line). */
function viaHttp(url: string, opts: { method?: string; body?: string; auth?: string | null } = {}): Promise<{ status: number; body: string; headers: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port: proxy.port, method: opts.method ?? "GET", path: url, headers: opts.auth === null ? {} : { "Proxy-Authorization": opts.auth ?? auth(), Host: new URL(url).host } },
      (res) => {
        let b = "";
        res.on("data", (c) => (b += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b, headers: res.headers }));
      },
    );
    r.on("error", reject);
    r.end(opts.body);
  });
}

/** HTTPS through the proxy: CONNECT, then TLS trusting Penteos's CA, then the request. */
function viaConnect(host: string, port: number, path: string): Promise<{ status: number; body: string; issuer: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port: proxy.port, method: "CONNECT", path: `${host}:${port}`, headers: { "Proxy-Authorization": auth() } });
    r.on("connect", (res, socket) => {
      if (res.statusCode !== 200) return reject(new Error(`CONNECT ${res.statusCode}`));
      const tls = tlsConnect({ socket, servername: host, ca: ca.certPem });
      tls.on("secureConnect", () => {
        const issuer = String(tls.getPeerCertificate().issuer.CN ?? "");
        tls.write(`GET ${path} HTTP/1.1\r\nHost: ${host}:${port}\r\nConnection: close\r\n\r\n`);
        let raw = "";
        tls.on("data", (c) => (raw += c));
        tls.on("end", () => resolve({ status: Number(raw.split(" ")[1]), body: raw.split("\r\n\r\n").slice(1).join("\r\n\r\n"), issuer }));
      });
      tls.on("error", reject);
    });
    r.on("error", reject);
    r.end();
  });
}

describe("intercepting proxy", () => {
  it("asks for the project credentials", async () => {
    expect((await viaHttp(`http://127.0.0.1:${httpPort}/`, { auth: null })).status).toBe(407);
    expect((await viaHttp(`http://127.0.0.1:${httpPort}/`, { auth: `Basic ${Buffer.from("nope:t0k").toString("base64")}` })).status).toBe(407);
  });

  it("forwards plain HTTP in scope, records the exchange and maps the endpoint", async () => {
    const r = await viaHttp(`http://127.0.0.1:${httpPort}/login.php?next=1`, { method: "POST", body: "user=a" });
    expect(r).toMatchObject({ status: 200, body: "POST /login.php?next=1 body=user=a" });
    const [entry] = eng.queryProxy();
    expect(entry).toMatchObject({ method: "POST", status: 200, inScope: true, blocked: false, source: "browser" });
    expect(eng.readRaw(entry!.rawId!).toString()).toContain("Set-Cookie: sid=abc");
    expect(eng.query({ kind: "endpoint" })[0]!.attributes).toMatchObject({ pathTemplate: "/login.php", methods: ["POST"] });
  });

  it("decrypts HTTPS with its own certificate and records it", async () => {
    const r = await viaConnect("127.0.0.1", httpsPort, "/secure");
    expect(r.status).toBe(200);
    expect(r.body).toContain("GET /secure");
    expect(r.issuer).toContain("Penteos CA");
    expect(eng.queryProxy()[0]!.url).toBe(`https://127.0.0.1:${httpsPort}/secure`);
  });

  it("blocks out-of-scope traffic and keeps a record of the attempt", async () => {
    const r = await viaHttp(`http://127.0.0.1:${outPort}/x`);
    expect(r.status).toBe(403);
    expect(r.headers["x-penteos"]).toBe("blocked");
    expect(eng.queryProxy()).toEqual([]); // hidden by default
    expect(eng.queryProxy({ includeBlocked: true })[0]).toMatchObject({ blocked: true, inScope: false });
  });

  it("says why it blocked, so the operator's browser can offer the way out", async () => {
    const out = await viaHttp(`http://127.0.0.1:${outPort}/x`);
    expect(out.headers["x-penteos-block"]).toBe("out_of_scope");
    expect(out.headers["x-penteos-host"]).toBe("127.0.0.1");
    eng.setInfo({ ...eng.info, stopWork: { active: true, by: human, at: new Date().toISOString(), reason: "pausa" } }, human);
    expect((await viaHttp(`http://127.0.0.1:${httpPort}/`)).headers["x-penteos-block"]).toBe("stop_work");
  });

  it("lets an out-of-scope host through the operator's browser for a while, still recorded as out of scope", async () => {
    const r = proxy.letThrough(eng.info.id, "127.0.0.1", 5);
    expect(Date.parse(r.until)).toBeGreaterThan(Date.now());
    const ok = await viaHttp(`http://127.0.0.1:${outPort}/una-vez`);
    expect(ok.status).toBe(200);
    expect(eng.queryProxy({ includeBlocked: true }).find((x) => x.url.endsWith("/una-vez"))).toMatchObject({ blocked: false });
    // The agents' browser never gets the operator's pass: it proposes scope rules instead.
    const agent = await viaHttp(`http://127.0.0.1:${outPort}/agente`, { auth: auth(`${eng.info.id}+agent`) });
    expect(agent.status).toBe(403);
    // Stop-work cannot be let through.
    eng.setInfo({ ...eng.info, stopWork: { active: true, by: human, at: new Date().toISOString(), reason: "pausa" } }, human);
    expect((await viaHttp(`http://127.0.0.1:${outPort}/x`)).status).toBe(403);
  });

  it("with 'passthrough', tunnels out-of-scope HTTPS without decrypting or recording it", async () => {
    settings = { ...settings, outOfScope: "passthrough" };
    const outHttps = await listen(createHttps(await ca.pemFor("localhost"), handler) as unknown as Server);
    const r = await viaConnect("localhost", outHttps, "/tercero");
    expect(r.status).toBe(200);
    expect(eng.queryProxy({ includeBlocked: true, includeStatic: true })).toEqual([]);
  });

  it("stores bodies decompressed and learns technologies", async () => {
    await viaHttp(`http://127.0.0.1:${httpPort}/gz`);
    const raw = eng.readRaw(eng.queryProxy()[0]!.rawId!).toString();
    expect(raw).toContain("<h1>comprimido</h1>");
    expect(eng.query({ kind: "webapp" })[0]!.attributes.technologies).toEqual([{ name: "nginx/1.25", confidence: 0.9 }]);
  });

  it("stop-work blocks everything", async () => {
    eng.setInfo({ ...eng.info, stopWork: { active: true, by: human, at: new Date().toISOString(), reason: "pedido del cliente" } }, human);
    const r = await viaHttp(`http://127.0.0.1:${httpPort}/`);
    expect(r.status).toBe(403);
    expect(r.body).toContain("Stop-work");
  });

  it("chains through an upstream proxy (like Burp)", async () => {
    // A second Penteos proxy plays the upstream; the first one goes through it.
    const upstream = new PenteosProxy(ws, ca, { token: "up", actor: human, settings: () => settings });
    await upstream.start(0);
    const chained = new PenteosProxy(ws, ca, { token: "t0k", actor: human, settings: () => settings, upstream: () => `http://${eng.info.id}+burp:up@127.0.0.1:${upstream.port}` });
    await proxy.close();
    proxy = chained;
    await proxy.start(0);
    const r = await viaHttp(`http://127.0.0.1:${httpPort}/chain`);
    expect(r.body).toBe("GET /chain body=");
    // Both proxies recorded it; the upstream one says where it came from.
    expect(eng.queryProxy().map((e) => e.source).sort()).toEqual(["browser", "burp"]);
    await upstream.close();
  });
});
