import { mkdtempSync, rmSync } from "node:fs";
import { request as httpRequest, type Server } from "node:http";
import { connect as http2Connect, createSecureServer, type Http2SecureServer } from "node:http2";
import { createServer as createHttps } from "node:https";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PenteosProxy, CertificateAuthority, DEFAULT_PROXY_SETTINGS, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let ca: CertificateAuthority;
let proxy: PenteosProxy;
let h2server: Http2SecureServer;
let h1server: Server;
let h2port = 0;
let h1port = 0;

const answer = (req: { httpVersion: string; method?: string; url?: string; headers: Record<string, unknown> }, res: { setHeader(k: string, v: string | string[]): void; end(b: string): void }) => {
  res.setHeader("set-cookie", ["a=1", "b=2"]);
  res.setHeader("x-version", req.httpVersion);
  res.end(`${req.httpVersion} ${req.method} ${req.url} host=${String(req.headers[":authority"] ?? req.headers.host)}`);
};

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-h2-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "H2", mode: "web" }, human);
  ca = await CertificateAuthority.load(join(dir, "ca"));
  const pem = await ca.pemFor("localhost");
  h2server = createSecureServer({ ...pem, allowHTTP1: true }, answer as never);
  await new Promise<void>((r) => h2server.listen(0, "127.0.0.1", () => r()));
  h2port = (h2server.address() as { port: number }).port;
  h1server = createHttps(pem, answer as never) as unknown as Server;
  await new Promise<void>((r) => h1server.listen(0, "127.0.0.1", () => r()));
  h1port = (h1server.address() as { port: number }).port;
  eng.addScopeRule({ effect: "include", target: { type: "domain", value: "localhost" } }, human);
  proxy = new PenteosProxy(ws, ca, { token: "t", actor: human, settings: () => DEFAULT_PROXY_SETTINGS });
  await proxy.start(0);
});

afterEach(async () => {
  await proxy.close();
  h2server.close();
  h1server.close();
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

/** A TLS connection to localhost:port through the proxy, offering these ALPN protocols. */
function tunnel(port: number, alpn: string[]): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port: proxy.port, method: "CONNECT", path: `localhost:${port}`, headers: { "Proxy-Authorization": `Basic ${Buffer.from(`${eng.info.id}:t`).toString("base64")}` } });
    r.on("connect", (_res, socket: Socket) => {
      const tls = tlsConnect({ socket, servername: "localhost", ca: ca.certPem, ALPNProtocols: alpn });
      tls.once("secureConnect", () => resolve(tls));
      tls.once("error", reject);
    });
    r.on("error", reject);
    r.end();
  });
}

function h2get(tls: TLSSocket, path: string, port: number): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    const session = http2Connect(`https://localhost:${port}`, { createConnection: () => tls });
    const s = session.request({ ":path": path, ":method": "GET" });
    let head: Record<string, unknown> = {};
    let body = "";
    s.on("response", (h) => (head = h));
    s.on("data", (c) => (body += c));
    s.on("end", () => {
      session.close();
      resolve({ status: Number(head[":status"]), headers: head, body });
    });
    s.on("error", reject);
    s.end();
  });
}

describe("HTTP/2 through the proxy", () => {
  it("speaks HTTP/2 with the client and the server when both can, and records it", async () => {
    const tls = await tunnel(h2port, ["h2", "http/1.1"]);
    expect(tls.alpnProtocol).toBe("h2");
    const r = await h2get(tls, "/api/items?x=1", h2port);
    expect(r.status).toBe(200);
    expect(r.body).toBe(`2.0 GET /api/items?x=1 host=localhost:${h2port}`);
    expect(r.headers["set-cookie"]).toEqual(["a=1", "b=2"]);
    const [entry] = eng.queryProxy();
    expect(entry).toMatchObject({ httpVersion: "2", status: 200, path: "/api/items?x=1" });
    expect(eng.readRaw(entry!.rawId!).toString()).toMatch(/^GET \/api\/items\?x=1 HTTP\/2/);
  });

  it("an HTTP/2 client and a server that only speaks HTTP/1.1: falls back upstream", async () => {
    const tls = await tunnel(h1port, ["h2", "http/1.1"]);
    const r = await h2get(tls, "/legacy", h1port);
    expect(r.body).toBe(`1.1 GET /legacy host=localhost:${h1port}`);
  });

  it("an HTTP/1.1 client stays on HTTP/1.1 even if the server could do HTTP/2", async () => {
    const tls = await tunnel(h2port, ["http/1.1"]);
    expect(tls.alpnProtocol).toBe("http/1.1");
    const body = await new Promise<string>((resolve) => {
      tls.write(`GET /one HTTP/1.1\r\nHost: localhost:${h2port}\r\nConnection: close\r\n\r\n`);
      let raw = "";
      tls.on("data", (c) => (raw += c));
      tls.on("end", () => resolve(raw.split("\r\n\r\n").slice(1).join("")));
    });
    expect(body).toBe(`1.1 GET /one host=localhost:${h2port}`);
  });
});

describe("HTTP/2 from the request editor", () => {
  const ctx = (): OperationContext => {
    const runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
    return { workspace: ws, caller: { actor: human, policy: { type: "human" } }, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner };
  };
  it("sends over HTTP/2 when the request line says so, and explains when the server cannot", async () => {
    const r = (await executeOperation("http.send", { origin: `https://localhost:${h2port}`, raw: "GET /h2 HTTP/2\n\n" }, ctx())) as { response: { status: number; body: string } };
    expect(r.response.body).toBe(`2.0 GET /h2 host=localhost:${h2port}`);
    const fail = (await executeOperation("http.send", { origin: `https://localhost:${h1port}`, raw: "GET /h2 HTTP/2\n\n" }, ctx())) as { status: string; error: string };
    expect(fail.status).toBe("failed");
    expect(fail.error).toContain("does not speak HTTP/2");
  });
});
