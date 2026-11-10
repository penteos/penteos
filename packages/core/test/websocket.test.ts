import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttp, request as httpRequest, type Server } from "node:http";
import { createServer as createHttps } from "node:https";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect as tlsConnect } from "node:tls";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import WebSocket, { WebSocketServer } from "ws";
import { PenteosProxy, CertificateAuthority, DEFAULT_PROXY_SETTINGS, type Engagement, encodeFrame, executeOperation, FrameReader, Interceptor, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };

describe("frame codec", () => {
  it("decodes masked and unmasked frames of every length, even byte by byte", () => {
    for (const len of [0, 5, 125, 126, 300, 65535, 70000]) {
      const payload = Buffer.alloc(len, 0x61);
      for (const mask of [true, false]) {
        const wire = encodeFrame(1, payload, mask);
        const r = new FrameReader();
        const frames = [...wire].flatMap((b) => r.push(Buffer.from([b])));
        expect(frames).toHaveLength(1);
        expect(frames[0]!.payload.equals(payload)).toBe(true);
        expect(frames[0]!.raw.equals(wire)).toBe(true);
      }
    }
  });
});

let dir: string;
let ws: Workspace;
let eng: Engagement;
let ca: CertificateAuthority;
let proxy: PenteosProxy;
let interceptor: Interceptor;
let httpServer: Server;
let httpsServer: Server;
let wss: WebSocketServer;
let wsss: WebSocketServer;
let port = 0;
let tlsPort = 0;
const serverSeen: string[] = [];
let serverExtensions = "";

function echo(server: WebSocketServer) {
  server.on("connection", (socket, req) => {
    serverExtensions = String(req.headers["sec-websocket-extensions"] ?? "");
    socket.on("message", (data, isBinary) => {
      const text = String(data);
      serverSeen.push(text);
      if (text === "fragmentado") {
        socket.send("parte 1, ", { fin: false });
        socket.send("parte 2", { fin: true });
      } else socket.send(isBinary ? data : `eco: ${text}`, { binary: isBinary });
    });
  });
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-ws-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "WS", mode: "web", maxRisk: "exploitation" }, human);
  ca = await CertificateAuthority.load(join(dir, "ca"));
  httpServer = createHttp();
  wss = new WebSocketServer({ server: httpServer, perMessageDeflate: true });
  echo(wss);
  await new Promise<void>((r) => httpServer.listen(0, "127.0.0.1", () => r()));
  port = (httpServer.address() as { port: number }).port;
  httpsServer = createHttps(await ca.pemFor("127.0.0.1")) as unknown as Server;
  wsss = new WebSocketServer({ server: httpsServer as never });
  echo(wsss);
  await new Promise<void>((r) => httpsServer.listen(0, "127.0.0.1", () => r()));
  tlsPort = (httpsServer.address() as { port: number }).port;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: `${port},${tlsPort}` }, human);
  interceptor = new Interceptor();
  proxy = new PenteosProxy(ws, ca, { token: "t", actor: human, settings: () => DEFAULT_PROXY_SETTINGS });
  proxy.hooks = { ws: (e, m) => interceptor.onWsMessage(e, m) };
  await proxy.start(0);
  serverSeen.length = 0;
});

afterEach(async () => {
  interceptor.releaseAll();
  await proxy.close();
  wss.close();
  wsss.close();
  httpServer.close();
  httpsServer.close();
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

/** A WebSocket client going through the proxy, the way a browser does (CONNECT tunnel). */
function viaProxy(target: string): Promise<WebSocket> {
  const u = new URL(target);
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port: proxy.port, method: "CONNECT", path: `${u.hostname}:${u.port}`, headers: { "Proxy-Authorization": `Basic ${Buffer.from(`${eng.info.id}:t`).toString("base64")}` } });
    r.on("connect", (_res, socket: Socket) => {
      const transport = u.protocol === "wss:" ? tlsConnect({ socket, servername: "localhost", ca: ca.certPem }) : socket;
      const client = new WebSocket(target, { createConnection: () => transport, perMessageDeflate: true } as never);
      client.once("open", () => resolve(client));
      client.once("error", reject);
    });
    r.on("error", reject);
    r.end();
  });
}

const next = (c: WebSocket) => new Promise<string>((r) => c.once("message", (d) => r(String(d))));
const until = async (f: () => boolean) => {
  for (let i = 0; i < 100 && !f(); i++) await new Promise((r) => setTimeout(r, 20));
};

describe("WebSockets through the proxy", () => {
  it("relays ws:// and wss://, records every message, and keeps compression off", async () => {
    for (const target of [`ws://127.0.0.1:${port}/chat`, `wss://127.0.0.1:${tlsPort}/chat`]) {
      const c = await viaProxy(target);
      const reply = next(c);
      c.send("hola");
      expect(await reply).toBe("eco: hola");
      c.close();
    }
    expect(serverExtensions).toBe(""); // the proxy did not offer permessage-deflate
    const entries = eng.queryProxy().filter((e) => e.status === 101);
    expect(entries).toHaveLength(2);
    await until(() => eng.queryWs(entries[0]!.id).length >= 2);
    const msgs = eng.queryWs(entries[1]!.id).map((m) => [m.direction, m.data]);
    expect(msgs.slice(0, 2)).toEqual([["out", "hola"], ["in", "eco: hola"]]);
  });

  it("records fragmented messages whole", async () => {
    const c = await viaProxy(`ws://127.0.0.1:${port}/`);
    const reply = next(c);
    c.send("fragmentado");
    expect(await reply).toBe("parte 1, parte 2");
    const entry = eng.queryProxy().find((e) => e.status === 101)!;
    await until(() => eng.queryWs(entry.id).some((m) => m.direction === "in"));
    expect(eng.queryWs(entry.id).filter((m) => m.direction === "in").map((m) => m.data)).toEqual(["parte 1, parte 2"]);
    c.close();
  });

  it("intercepts a message and sends the edited version", async () => {
    eng.setMeta("intercept", { wsMessages: true }, human);
    const c = await viaProxy(`ws://127.0.0.1:${port}/`);
    c.send('{"role":"user"}');
    await until(() => interceptor.list().length > 0);
    const [pending] = interceptor.list();
    expect(pending).toMatchObject({ kind: "ws_out", raw: '{"role":"user"}' });
    const reply = next(c);
    interceptor.decide(pending!.id, { action: "forward", raw: '{"role":"admin"}' });
    // The answer from the server is intercepted too: let it through.
    await until(() => interceptor.list().length > 0);
    interceptor.releaseAll();
    expect(await reply).toBe('eco: {"role":"admin"}');
    expect(serverSeen).toEqual(['{"role":"admin"}']);
    const entry = eng.queryProxy().find((e) => e.status === 101)!;
    expect(eng.queryWs(entry.id)[0]).toMatchObject({ direction: "out", data: '{"role":"admin"}', edited: true });
    c.close();
  });
});

const cleanup: Array<() => void> = [];
afterEach(() => {
  for (const f of cleanup.splice(0)) f();
});

describe("WebSocket repeater", () => {
  const ctx = (actor: Actor): OperationContext => ({
    workspace: ws,
    caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "passive" } : { type: "human" } },
    defaultEngagementId: eng.info.id,
    engagement: () => eng,
    runner: (() => {
      const r = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
      return () => r;
    })(),
  });

  it("opens, sends with secrets, records, closes - and follows the rules", async () => {
    const c = ctx(human);
    cleanup.push(() => c.runner().closeAllWs());
    await executeOperation("secret.save", { name: "tok", kind: "token", value: "S3CRETO" }, c);
    const open = (await executeOperation("ws.open", { url: `ws://127.0.0.1:${port}/api`, headers: "Origin: http://127.0.0.1" }, c)) as { status: string; sessionId: string; entryId: string };
    expect(open.status).toBe("open");
    await executeOperation("ws.send", { sessionId: open.sessionId, text: "auth {{secret:tok}}" }, c);
    await until(() => eng.queryWs(open.entryId).length >= 2);
    expect(serverSeen).toEqual(["auth S3CRETO"]);
    // Recorded with the reference; the echo comes back redacted for agents.
    const msgs = (await executeOperation("ws.messages", { entryId: open.entryId }, ctx(agent))) as Array<{ direction: string; data: { content: string } }>;
    expect(msgs.map((m) => m.data.content)).toEqual(["auth {{secret:tok}}", "eco: auth {{secret:tok}}"]);
    expect(await executeOperation("ws.close", { sessionId: open.sessionId }, c)).toEqual({ closed: true });

    await expect(executeOperation("ws.open", { url: "ws://example.com/x" }, c)).rejects.toMatchObject({ code: "OUT_OF_SCOPE" });
    const asked = (await executeOperation("ws.open", { url: `ws://127.0.0.1:${port}/api` }, ctx(agent))) as { status: string };
    expect(asked.status).toBe("pending_approval");
  });
});
