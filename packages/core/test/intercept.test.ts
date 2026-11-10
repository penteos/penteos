import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttp, request as httpRequest, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PenteosProxy, CertificateAuthority, DEFAULT_PROXY_SETTINGS, type Engagement, executeOperation, Interceptor, type OperationContext, type ReplaceRule, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let proxy: PenteosProxy;
let interceptor: Interceptor;
let target: Server;
let port = 0;
let seen: { method?: string; url?: string; headers?: Record<string, unknown>; body?: Buffer } = {};

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-icpt-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Intercept", mode: "web" }, human);
  target = createHttp((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      seen = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) };
      if (req.url === "/gz") {
        res.writeHead(200, { "Content-Type": "text/html", "Content-Encoding": "gzip", "Content-Security-Policy": "default-src 'self'" });
        return res.end(gzipSync("<p>hola admin</p>"));
      }
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
  });
  await new Promise<void>((r) => target.listen(0, "127.0.0.1", () => r()));
  port = (target.address() as { port: number }).port;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, human);
  const ca = await CertificateAuthority.load(join(dir, "ca"));
  interceptor = new Interceptor();
  proxy = new PenteosProxy(ws, ca, { token: "t", actor: human, settings: () => DEFAULT_PROXY_SETTINGS });
  proxy.hooks = { request: (e, req) => interceptor.onRequest(e, req), response: (e, req, res) => interceptor.onResponse(e, req, res) };
  await proxy.start(0);
});

afterEach(async () => {
  interceptor.releaseAll();
  await proxy.close();
  target.close();
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

function send(path: string, opts: { method?: string; body?: Buffer | string; headers?: Record<string, string> } = {}): Promise<{ status: number; body: string; headers: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port: proxy.port, method: opts.method ?? "GET", path: `http://127.0.0.1:${port}${path}`, headers: { "Proxy-Authorization": `Basic ${Buffer.from(`${eng.info.id}:t`).toString("base64")}`, Host: `127.0.0.1:${port}`, ...(opts.headers ?? {}) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString(), headers: res.headers }));
      },
    );
    r.on("error", reject);
    r.end(opts.body);
  });
}

const waitPending = async (n = 1) => {
  for (let i = 0; i < 100; i++) {
    if (interceptor.list().length >= n) return interceptor.list();
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error("nothing intercepted");
};

const rules = (list: Array<Partial<ReplaceRule>>) => eng.setMeta("proxyRules", list.map((r, i) => ({ id: String(i), enabled: true, regex: false, match: "", replace: "", ...r })), human);

describe("replace rules", () => {
  it("replace, add and remove headers; edit compressed bodies; rewrite URLs", async () => {
    rules([
      { target: "request_header", match: "Mozilla", replace: "Penteos" },
      { target: "request_header", match: "", replace: "X-Pentest: penteos" },
      { target: "request_url", match: "/viejo", replace: "/nuevo" },
      { target: "response_header", match: "^Content-Security-Policy:.*$", regex: true, replace: "" },
      { target: "response_body", match: "admin", replace: "operador" },
    ]);
    await send("/viejo", { headers: { "User-Agent": "Mozilla/5.0" } });
    expect(seen.url).toBe("/nuevo");
    expect(seen.headers).toMatchObject({ "user-agent": "Penteos/5.0", "x-pentest": "penteos" });
    const r = await send("/gz");
    expect(r.body).toBe("<p>hola operador</p>"); // decompressed, edited, sent uncompressed
    expect(r.headers["content-security-policy"]).toBeUndefined();
    expect(r.headers["content-encoding"]).toBeUndefined();
    expect(eng.queryProxy().every((e) => e.edited)).toBe(true);
  });
});

describe("interception", () => {
  it("holds a request until the operator forwards it edited", async () => {
    eng.setMeta("intercept", { requests: true }, human);
    const pending = send("/login.php", { method: "POST", body: "user=a&pass=b", headers: { "Content-Type": "application/x-www-form-urlencoded" } });
    const [msg] = await waitPending();
    expect(msg!.raw).toContain("POST /login.php HTTP/1.1");
    expect(msg!.raw.endsWith("user=a&pass=b")).toBe(true);
    interceptor.decide(msg!.id, { action: "forward", raw: msg!.raw.replace("user=a", "user=admin") });
    expect((await pending).status).toBe(200);
    expect(seen.body!.toString()).toBe("user=admin&pass=b");
    expect(Number(seen.headers!["content-length"])).toBe("user=admin&pass=b".length);
  });

  it("records the time held for the operator apart from the network time", async () => {
    eng.setMeta("intercept", { requests: true }, human);
    const pending = send("/lento");
    const [msg] = await waitPending();
    await new Promise((r) => setTimeout(r, 300));
    interceptor.decide(msg!.id, { action: "forward" });
    await pending;
    const [entry] = eng.queryProxy();
    expect(entry!.heldMs).toBeGreaterThanOrEqual(250);
    expect(entry!.durationMs!).toBeLessThan(200);
  });

  it("drops a request; rejects a malformed edit and keeps it waiting", async () => {
    eng.setMeta("intercept", { requests: true }, human);
    const p1 = send("/a");
    const [msg] = await waitPending();
    expect(() => interceptor.decide(msg!.id, { action: "forward", raw: "esto no es un request" })).toThrow(/first line/);
    expect(interceptor.list()).toHaveLength(1);
    interceptor.decide(msg!.id, { action: "drop" });
    expect((await p1).status).toBe(418);
    expect(eng.queryProxy({ includeBlocked: true })[0]).toMatchObject({ blocked: true, reason: "Dropped by the operator" });
  });

  it("forwards binary bodies byte for byte when left untouched", async () => {
    eng.setMeta("intercept", { requests: true }, human);
    const blob = Buffer.from([0, 1, 2, 255, 254, 0x89, 0x50, 0x4e, 0x47]);
    const p = send("/upload", { method: "POST", body: blob, headers: { "Content-Type": "application/octet-stream" } });
    const [msg] = await waitPending();
    expect(msg!.binaryBody).toBe(true);
    // The operator changes a header but not the (binary) body.
    interceptor.decide(msg!.id, { action: "forward", raw: msg!.raw.replace("application/octet-stream", "application/octet-stream\nX-Edited: 1") });
    await p;
    expect(seen.body!.equals(blob)).toBe(true);
    expect(seen.headers!["x-edited"]).toBe("1");
  });

  it("an edited request that leaves the scope is blocked", async () => {
    eng.setMeta("intercept", { requests: true }, human);
    const p = send("/a");
    const [msg] = await waitPending();
    interceptor.decide(msg!.id, { action: "forward", raw: msg!.raw.replace(`Host: 127.0.0.1:${port}`, "Host: example.com") });
    expect((await p).status).toBe(403);
  });

  it("intercepts responses and releases everything when turned off", async () => {
    eng.setMeta("intercept", { responses: true }, human);
    const p = send("/gz");
    const [msg] = await waitPending();
    expect(msg!.kind).toBe("response");
    expect(msg!.raw).toContain("<p>hola admin</p>"); // shown decompressed
    expect(interceptor.releaseAll(eng.info.id)).toBe(1);
    // Untouched: it goes out exactly as the server sent it (still gzip).
    const r = await p;
    expect(r.headers["content-encoding"]).toBe("gzip");
  });
});

describe("encodings", () => {
  it("decodes zstd bodies (what Chromium asks for first)", async () => {
    const z = (await import("node:zlib")) as unknown as { zstdCompressSync?: (b: Buffer) => Buffer };
    if (!z.zstdCompressSync) return;
    const { decodeBody } = await import("../src/index.js");
    const packed = z.zstdCompressSync(Buffer.from("<h1>zstd</h1>"));
    expect(decodeBody(packed, [["Content-Encoding", "zstd"]])?.toString()).toBe("<h1>zstd</h1>");
  });
});

describe("the Maestro runs the proxy", () => {
  const agent: Actor = { type: "agent", id: "01JA0000000000000000000AGT" };
  const ctx = (actor: Actor, autonomy: "with_approval" | "autonomous" = "autonomous"): OperationContext => {
    const runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
    return {
      workspace: ws,
      caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy, maxRisk: "active" } : { type: "human" } },
      defaultEngagementId: eng.info.id,
      engagement: () => eng,
      runner: () => runner,
      proxy: { status: () => ({ running: true, host: "127.0.0.1", port: proxy.port, token: "t", caFingerprint: "" }), ca: () => ({ pem: "", derBase64: "", fingerprint: "" }), setUpstream: () => {}, interceptor, letThrough: (id, host, min) => proxy.letThrough(id, host, min) },
    };
  };
  const notices = () => {
    const out: string[] = [];
    eng.events.on("change", (e: { type: string; text?: string }) => e.type === "proxy.agent_changed" && out.push(e.text!));
    return out;
  };

  it("turns interception off with a reason, releasing what was held, and the operator is told", async () => {
    const seen = notices();
    await executeOperation("intercept.configure", { requests: true, reason: "capturar el login" }, ctx(agent));
    const pending = send("/x");
    await waitPending();
    expect(((await executeOperation("intercept.state", {}, ctx(agent))) as { pending: Array<{ url: string; raw?: string }> }).pending[0]).toMatchObject({ url: expect.stringContaining("/x") });
    await expect(executeOperation("intercept.configure", { requests: false }, ctx(agent))).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    expect(await executeOperation("intercept.configure", { requests: false, reason: "ya capturé el login" }, ctx(agent))).toMatchObject({ requests: false, released: 1 });
    expect((await pending).status).toBe(200);
    expect(seen).toEqual(["Interception on (requests): capturar el login", "Interception off: ya capturé el login"]);
  });

  it("does not cut short what the operator may be editing", async () => {
    await executeOperation("intercept.configure", { responses: true }, ctx(human));
    const pending = send("/y");
    await waitPending();
    await expect(executeOperation("intercept.release_all", { reason: "frena el navegador" }, ctx(agent))).rejects.toThrow(/may be editing/);
    await expect(executeOperation("intercept.configure", { responses: false, reason: "x" }, ctx(agent))).rejects.toThrow(/may be editing/);
    expect(await executeOperation("intercept.release_all", {}, ctx(human))).toEqual({ released: 1 });
    await pending;
  });

  it("sets replace rules on its own when autonomous, otherwise asks", async () => {
    const rule = { target: "request_header", match: "", replace: "X-Pentest: penteos" };
    await expect(executeOperation("proxy.set_rules", { rules: [rule] }, ctx(agent))).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await executeOperation("proxy.set_rules", { rules: [rule], reason: "marcar el tráfico de la prueba" }, ctx(agent));
    await send("/z");
    expect(seen.headers).toMatchObject({ "x-pentest": "penteos" });

    const c = ctx(agent, "with_approval");
    const r = (await executeOperation("proxy.set_rules", { rules: [], reason: "ya no hace falta" }, c)) as { status: string; approvalId: string };
    expect(r.status).toBe("pending_approval");
    expect(interceptor.rules(eng)).toHaveLength(1);
    const approval = c.runner().listApprovals()[0]!;
    expect(approval.summary).toBe("Remove all proxy replace rules");
    await c.runner().resolveApproval(approval.id, true, human);
    expect(interceptor.rules(eng)).toHaveLength(0);
  });
});
