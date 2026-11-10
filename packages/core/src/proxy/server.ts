import { type Actor, INGEST_FORMAT, type IngestItem, ulid } from "@penteos/schema";
import { createServer as createH2Server } from "node:http2";
import { createServer, request as httpRequest, type IncomingMessage, type OutgoingHttpHeaders, type Server, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as netConnect, type Socket } from "node:net";
import { Duplex } from "node:stream";
import { connect as tlsConnect, TLSSocket } from "node:tls";
import * as zlib from "node:zlib";
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";

/** zstd (what Chromium asks for first) where this Node has it. */
const zstd = (zlib as unknown as { zstdDecompressSync?: (b: Buffer) => Buffer }).zstdDecompressSync;
import type { Engagement } from "../engagement.js";
import { AGENT_BROWSER_SOURCE, isBrowserHousekeeping } from "../browser/agent-browser.js";
import type { Workspace } from "../workspace.js";
import type { CertificateAuthority } from "./ca.js";
import { sendH2 } from "../http.js";
import { encodeFrame, type Frame, FrameReader, OP } from "./websocket.js";

/**
 * Penteos's intercepting proxy. The project browser (or Burp, Caido, ZAP, curl -x) sends its
 * traffic here; every request is checked against the engagement's scope, recorded in its
 * history with the full exchange as raw evidence, and its endpoint lands in the graph.
 *
 *   client ──CONNECT──▶ proxy ──(TLS with a Penteos certificate)──▶ request pipeline ──▶ target
 *
 * The pipeline (request → replace rules → interception → upstream → response → rules →
 * interception) is where everything else plugs in.
 *
 * Which engagement a request belongs to travels in the proxy credentials:
 * Proxy-Authorization: Basic base64("<engagementId>:<proxy token>").
 */

export interface ProxyRequest {
  method: string;
  url: URL;
  headers: Array<[string, string]>;
  body: Buffer;
  /** The protocol the client used (the upstream connection mirrors it when it can). */
  version?: "1.1" | "2";
}

export interface ProxyResponse {
  status: number;
  statusText: string;
  headers: Array<[string, string]>;
  body: Buffer;
  version?: "1.1" | "2";
}

/** What came back from the target: whole (body) or still streaming (stream). */
interface Upstream {
  status: number;
  statusText: string;
  headers: Array<[string, string]>;
  version: "1.1" | "2";
  body?: Buffer;
  stream?: NodeJS.ReadableStream;
}

export interface ProxySettings {
  /** What happens to out-of-scope traffic: blocked (default) or tunnelled without recording. */
  outOfScope: "block" | "passthrough";
  /** Keep bodies of images, fonts, styles and scripts (off: only their headers). */
  recordStatic: boolean;
}

/** Why the proxy refused a request: the kind decides what the operator's browser offers. */
export interface Block {
  kind: "out_of_scope" | "stop_work" | "outside_window" | "other";
  host: string;
  reason: string;
  /** What the operator should read as is: the stop-work's reason. */
  detail?: string;
}

export const DEFAULT_PROXY_SETTINGS: ProxySettings = { outOfScope: "block", recordStatic: false };

/** Hooks for stage 2 (replace rules, interception). Returning undefined drops the message. */
export interface ProxyHooks {
  ws?(engagement: Engagement, m: { url: string; direction: "out" | "in"; opcode: number; payload: Buffer }): Promise<{ payload: Buffer; opcode: number; edited: boolean } | undefined>;
  request?(engagement: Engagement, req: ProxyRequest, ctx: { source: string }): Promise<{ req: ProxyRequest; edited: boolean } | undefined>;
  response?(engagement: Engagement, req: ProxyRequest, res: ProxyResponse, ctx: { source: string }): Promise<{ res: ProxyResponse; edited: boolean } | undefined>;
}

interface Ctx {
  engagementId: string;
  source: string;
  /** Set for decrypted CONNECT tunnels. */
  tunnel?: { host: string; port: number; secure: boolean };
  /** The client speaks HTTP/2 on this connection. */
  h2?: boolean;
}

const MAX_REQUEST = 50 * 1024 * 1024;
const MAX_BUFFERED_RESPONSE = 25 * 1024 * 1024;
const MAX_RECORDED_BODY = 2 * 1024 * 1024;
const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "trailer", "upgrade", "transfer-encoding"]);
const STATIC_EXT = /\.(png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|css|js|mjs|map|mp4|webm|mp3|wav|ogg|pdf|zip)$/i;
const BINARY_MIME = /^(image|audio|video|font)\/|application\/(octet-stream|zip|gzip|pdf|x-protobuf|wasm|vnd\.|x-font)/i;

export class PenteosProxy {
  private server?: Server;
  private readonly inner: Server;
  private readonly tunnels = new WeakMap<Socket, Ctx>();
  /** Every socket the proxy holds (clients and upstreams), to close them all on shutdown. */
  private readonly sockets = new Set<{ destroy(): void }>();
  private track<T extends { destroy(): void; once(event: "close", cb: () => void): unknown }>(s: T): T {
    this.sockets.add(s);
    s.once("close", () => this.sockets.delete(s));
    return s;
  }
  port = 0;
  hooks: ProxyHooks = {};
  /** The port asked for (the proxy may be on another one when it was taken). */
  requestedPort = 0;

  constructor(
    private readonly workspace: Workspace,
    private readonly ca: CertificateAuthority,
    private readonly options: { token: string; actor: Actor; upstream?: () => string | undefined; settings: (e: Engagement) => ProxySettings },
  ) {
    // Requests from decrypted tunnels arrive here, already parsed.
    this.inner = createServer({ requestTimeout: 0, keepAliveTimeout: 30_000 });
    this.inner.on("request", (req, res) => {
      const ctx = this.tunnels.get(req.socket as Socket);
      if (!ctx) return void res.destroy();
      void this.handle(req, res, ctx);
    });
    this.inner.on("upgrade", (req, socket, head) => {
      const ctx = this.tunnels.get(req.socket as Socket);
      if (!ctx) return void socket.destroy();
      void this.handleUpgrade(req, socket as Socket, head, ctx);
    });
    this.inner.on("clientError", (_e, socket) => socket.destroy());
  }

  async start(port: number, host = "127.0.0.1"): Promise<number> {
    const server = createServer({ requestTimeout: 0, keepAliveTimeout: 30_000 });
    server.on("request", (req, res) => {
      const ctx = this.authenticate(req);
      if (!ctx) return this.askForCredentials(res);
      // Plain HTTP through the proxy: the request line carries the absolute URL.
      void this.handle(req, res, ctx);
    });
    server.on("connect", (req, socket: Socket, head) => this.handleConnect(req, socket, head));
    server.on("upgrade", (req, socket: Socket, head) => {
      const ctx = this.authenticate(req);
      if (!ctx) return void socket.end("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Penteos\"\r\n\r\n");
      void this.handleUpgrade(req, socket, head, ctx);
    });
    server.on("clientError", (_e, socket) => socket.destroy());
    server.on("connection", (s: Socket) => this.track(s));
    const listen = (p: number) =>
      new Promise<number>((resolve, reject) => {
        server.once("error", reject);
        server.listen(p, host, () => {
          server.off("error", reject);
          resolve((server.address() as { port: number }).port);
        });
      });
    // The preferred port, else the next few (a browser set up for it rarely needs much of a change),
    // else any free one. The status says which, and that it moved.
    this.requestedPort = port;
    const tries = port === 0 ? [0] : [...Array.from({ length: 11 }, (_, i) => port + i).filter((p) => p <= 65535), 0];
    let last: unknown;
    for (const p of tries) {
      try {
        this.port = await listen(p);
        last = undefined;
        break;
      } catch (e) {
        last = e;
        if ((e as NodeJS.ErrnoException).code !== "EADDRINUSE") throw e;
      }
    }
    if (last) throw last;
    this.server = server;
    return this.port;
  }

  close(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    this.sockets.clear();
    return new Promise((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }

  // -------------------------------------------------------------------------------------------
  // Connections

  private authenticate(req: IncomingMessage): Ctx | undefined {
    const header = req.headers["proxy-authorization"];
    const m = /^Basic\s+(.+)$/i.exec(Array.isArray(header) ? header[0]! : (header ?? ""));
    if (!m) return undefined;
    const [user, pass] = Buffer.from(m[1]!, "base64").toString("utf8").split(":");
    if (!user || pass !== this.options.token) return undefined;
    // "<engagementId>" or "<engagementId>+<source>" (e.g. "+burp") to tell tools apart.
    const [engagementId, source] = user.split("+");
    try {
      this.workspace.get(engagementId!);
    } catch {
      return undefined;
    }
    return { engagementId: engagementId!, source: source || "browser" };
  }

  private askForCredentials(res: ServerResponse): void {
    res.writeHead(407, { "Proxy-Authenticate": 'Basic realm="Penteos"', "Content-Type": "text/plain; charset=utf-8" });
    res.end("Penteos: this proxy requires the project credentials (user = project id, password = proxy token).");
  }

  private handleConnect(req: IncomingMessage, socket: Socket, head: Buffer): void {
    socket.on("error", () => socket.destroy());
    const ctx = this.authenticate(req);
    if (!ctx) return void socket.end("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Penteos\"\r\n\r\n");
    const [host, portText] = splitHostPort(req.url ?? "");
    const port = Number(portText) || 443;
    if (!host) return void socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    const engagement = this.workspace.get(ctx.engagementId);

    // Out-of-scope hosts with "passthrough": a blind tunnel, nothing decrypted or recorded.
    if (this.options.settings(engagement).outOfScope === "passthrough" && !this.hostMayBeInScope(engagement, host, port)) {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      void this.openUpstream(host, port).then(
        (up) => {
          if (head.length) up.write(head);
          socket.pipe(up).pipe(socket);
          up.on("error", () => socket.destroy());
        },
        () => socket.destroy(),
      );
      return;
    }

    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    const start = (first: Buffer) => {
      socket.pause();
      // The first bytes were already read (to tell TLS from plain HTTP): a stream that hands
      // them back first, so neither TLS nor the HTTP parser miss them.
      const stream = replay(socket, first);
      if (first[0] === 0x16) {
        // TLS: present a certificate for the host the client asked for.
        const tls = new TLSSocket(stream as unknown as Socket, {
          isServer: true,
          // HTTP/2 when the client offers it; HTTP/1.1 otherwise.
          ALPNProtocols: ["h2", "http/1.1"],
          SNICallback: (servername, cb) => {
            this.ca.contextFor(servername || host).then(
              (c) => cb(null, c),
              (e: Error) => cb(e),
            );
          },
        });
        tls.on("error", () => tls.destroy());
        tls.once("secure", () => {
          const tunnelCtx: Ctx = { ...ctx, tunnel: { host, port, secure: true } };
          if (tls.alpnProtocol === "h2") {
            // One HTTP/2 server per connection: its requests go through the same pipeline.
            const h2 = createH2Server();
            h2.on("request", (req, res) => void this.handle(req as unknown as IncomingMessage, res as unknown as ServerResponse, { ...tunnelCtx, h2: true }));
            h2.on("sessionError", () => tls.destroy());
            // HTTP/2 runs on a plain JS stream over the TLS socket (Node's supported path for
            // HTTP/2 over arbitrary streams; the TLS socket itself sits on a JS stream already).
            h2.emit("connection", replay(tls, Buffer.alloc(0)));
          } else {
            this.tunnels.set(tls, tunnelCtx);
            this.inner.emit("connection", tls);
          }
        });
      } else {
        // Plain HTTP inside a CONNECT (websockets on :80, some tools).
        this.tunnels.set(stream as unknown as Socket, { ...ctx, tunnel: { host, port, secure: false } });
        this.inner.emit("connection", stream);
      }
    };
    if (head.length) start(head);
    else socket.once("data", start);
  }

  /** Whether some include rule could cover this host (path rules are checked per request). */
  private hostMayBeInScope(engagement: Engagement, host: string, port: number): boolean {
    for (const target of [`${host}:${port}`, host, `https://${host}:${port}/`, `http://${host}:${port}/`]) {
      if (engagement.checkScope(target, "passive", { type: "human" }).decision !== "deny") return true;
    }
    return false;
  }

  /** A socket to host:port, directly or through the configured upstream proxy (Burp, Caido…). */
  private openUpstream(host: string, port: number): Promise<Socket> {
    const upstream = this.options.upstream?.();
    return new Promise((resolve, reject) => {
      if (!upstream) {
        const s = this.track(netConnect({ host, port }));
        s.setTimeout(30_000, () => s.destroy(new Error(`no TCP connection to ${host}:${port} after 30 s (a firewall dropping this machine's traffic, or the host is down)`)));
        s.once("connect", () => {
          s.setTimeout(0);
          resolve(s);
        });
        s.once("error", reject);
        return;
      }
      const u = new URL(upstream);
      const auth = u.username ? { "Proxy-Authorization": `Basic ${Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString("base64")}` } : {};
      const r = httpRequest({ host: u.hostname, port: Number(u.port) || 8080, method: "CONNECT", path: `${host}:${port}`, headers: { Host: `${host}:${port}`, ...auth } });
      r.setTimeout(30_000, () => r.destroy(new Error("the upstream proxy does not answer")));
      r.once("connect", (res, socket) => {
        if (res.statusCode === 200) resolve(this.track(socket));
        else {
          socket.destroy();
          reject(new Error(`the upstream proxy answered ${res.statusCode}`));
        }
      });
      r.once("error", reject);
      r.end();
    });
  }

  // -------------------------------------------------------------------------------------------
  // The request pipeline

  private async handle(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
    const started = Date.now();
    let engagement: Engagement;
    try {
      engagement = this.workspace.get(ctx.engagementId);
    } catch {
      return void res.destroy();
    }
    let preq: ProxyRequest;
    try {
      preq = { method: (req.method ?? "GET").toUpperCase(), url: this.urlOf(req, ctx), headers: requestHeaders(req), body: await readBody(req, MAX_REQUEST), version: ctx.h2 ? "2" : "1.1" };
    } catch (e) {
      return this.reply(res, 400, `Could not read the request: ${(e as Error).message}`);
    }
    const settings = this.options.settings(engagement);
    const isStatic = STATIC_EXT.test(preq.url.pathname);

    // The agents' browser's own housekeeping (Google accounts, check-in…): refused, never recorded.
    if (ctx.source === AGENT_BROWSER_SOURCE && isBrowserHousekeeping(preq.url.href)) return this.reply(res, 403, "browser housekeeping refused", preq.url);

    // Scope and stop-work: the same rules as every other action.
    const block = this.blockReason(engagement, preq.url, ctx.source);
    if (block) {
      this.record(engagement, ctx, preq, undefined, { blocked: true, reason: block.reason, started, isStatic, inScope: false });
      return this.reply(res, 403, block.reason, preq.url, block);
    }

    let edited = false;
    // Time waiting for the operator in interception: kept apart so it never reads as a slow server.
    const held = { ms: 0 };
    const hold = async <T>(p: Promise<T>): Promise<T> => {
      const t = Date.now();
      try {
        return await p;
      } finally {
        held.ms += Date.now() - t;
      }
    };
    if (this.hooks.request) {
      const r = await hold(this.hooks.request(engagement, preq, { source: ctx.source }));
      if (!r) {
        this.record(engagement, ctx, preq, undefined, { blocked: true, reason: "Dropped by the operator", started, held, isStatic, inScope: true, edited: true });
        return this.reply(res, 499, "Request dropped from Penteos.");
      }
      // An edited request must still be in scope (the URL may have changed).
      const again = r.req.url.href !== preq.url.href ? this.blockReason(engagement, r.req.url, ctx.source) : undefined;
      if (again) {
        this.record(engagement, ctx, r.req, undefined, { blocked: true, reason: again.reason, started, held, isStatic, inScope: false, edited: true });
        return this.reply(res, 403, again.reason, r.req.url, again);
      }
      preq = r.req;
      edited = r.edited;
    }

    let upstream: Upstream;
    try {
      upstream = await this.forward(preq);
    } catch (e) {
      const message = (e as Error).message;
      this.record(engagement, ctx, preq, undefined, { error: message, started, held, isStatic, inScope: true, edited });
      return this.reply(res, 502, `Penteos could not reach the server: ${message}`, preq.url);
    }

    const head = { status: upstream.status, statusText: upstream.statusText, headers: upstream.headers, version: upstream.version };
    if (upstream.body) {
      let pres: ProxyResponse = { ...head, body: upstream.body };
      if (this.hooks.response) {
        const r = await hold(this.hooks.response(engagement, preq, pres, { source: ctx.source }));
        if (!r) {
          this.record(engagement, ctx, preq, pres, { started, held, isStatic, inScope: true, edited: true, reason: "Response dropped by the operator" });
          return this.reply(res, 499, "Response dropped from Penteos.");
        }
        pres = r.res;
        edited = edited || r.edited;
      }
      const headers = pres.headers.filter(([k]) => !HOP_BY_HOP.has(k.toLowerCase()) && k.toLowerCase() !== "content-length");
      headers.push(["Content-Length", String(pres.body.length)]);
      writeHead(res, ctx, pres.status, pres.statusText, headers);
      res.end(pres.body);
      this.record(engagement, ctx, preq, pres, { started, held, isStatic, inScope: true, edited, recordStatic: settings.recordStatic });
      return;
    }

    // Too big (or a stream) to hold: pass it through as it comes, record the beginning.
    writeHead(res, ctx, head.status, head.statusText, head.headers.filter(([k]) => !HOP_BY_HOP.has(k.toLowerCase())));
    const kept: Buffer[] = [];
    let size = 0;
    const stream = upstream.stream!;
    stream.on("data", (c: Buffer) => {
      if (size < MAX_RECORDED_BODY) kept.push(c);
      size += c.length;
    });
    stream.pipe(res as unknown as NodeJS.WritableStream);
    stream.on("end", () =>
      this.record(engagement, ctx, preq, { ...head, body: Buffer.concat(kept) }, { started, held, isStatic, inScope: true, edited, recordStatic: settings.recordStatic, streamedSize: size }),
    );
    stream.on("error", () => res.destroy());
  }

  private urlOf(req: IncomingMessage, ctx: Ctx): URL {
    const raw = req.url ?? "/";
    if (/^https?:\/\//i.test(raw)) return new URL(raw);
    const t = ctx.tunnel;
    if (!t) throw new Error("request without an absolute URL");
    const defaultPort = t.secure ? 443 : 80;
    return new URL(`${t.secure ? "https" : "http"}://${t.host.includes(":") ? `[${t.host}]` : t.host}${t.port === defaultPort ? "" : `:${t.port}`}${raw.startsWith("/") ? raw : `/${raw}`}`);
  }

  /**
   * Why a request may not go out, if it may not. The kind travels to the operator's browser, which
   * offers the matching way out (add to scope, let through, lift the pause) or only explains it.
   */
  private blockReason(engagement: Engagement, url: URL, source: string): Block | undefined {
    const info = engagement.info;
    const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (info.stopWork?.active) return { kind: "stop_work", host, reason: `Stop-work active: ${info.stopWork.reason}`, detail: info.stopWork.reason };
    const d = engagement.checkScope(url.href, "active", { type: "human" });
    if (d.decision !== "deny") return undefined;
    if (d.code === "OUTSIDE_WINDOW") return { kind: "outside_window", host, reason: `Outside the dates: ${d.reason}` };
    // Let through by the operator, for a while: only their own browser, never the agents'.
    if (d.code === "OUT_OF_SCOPE" && source !== AGENT_BROWSER_SOURCE && this.isLetThrough(engagement.info.id, host)) return undefined;
    return { kind: d.code === "OUT_OF_SCOPE" ? "out_of_scope" : "other", host, reason: `Out of scope: ${d.reason}` };
  }

  /** Hosts the operator let through without adding them to scope, per project, until they expire. */
  private readonly letThroughs = new Map<string, Map<string, number>>();

  private isLetThrough(engagementId: string, host: string): boolean {
    const hosts = this.letThroughs.get(engagementId);
    const until = hosts?.get(host);
    if (until === undefined) return false;
    if (until > Date.now()) return true;
    hosts!.delete(host);
    return false;
  }

  /**
   * The operator lets one out-of-scope host through their own browser for a while (default 15
   * minutes), without a scope rule. Traffic is still recorded, marked out of scope.
   */
  letThrough(engagementId: string, host: string, minutes = 15): { host: string; until: string } {
    const h = host.replace(/^\[|\]$/g, "").toLowerCase();
    const until = Date.now() + Math.max(1, Math.min(240, minutes)) * 60_000;
    let hosts = this.letThroughs.get(engagementId);
    if (!hosts) this.letThroughs.set(engagementId, (hosts = new Map()));
    hosts.set(h, until);
    return { host: h, until: new Date(until).toISOString() };
  }

  private async forward(req: ProxyRequest): Promise<Upstream> {
    const secure = req.url.protocol === "https:";
    const port = Number(req.url.port) || (secure ? 443 : 80);
    const host = req.url.hostname.replace(/^\[|\]$/g, "");
    const pairsOut: Array<[string, string]> = [];
    for (const [k, v0] of req.headers) {
      const key = k.toLowerCase();
      if (HOP_BY_HOP.has(key) || key === "content-length") continue;
      // Never ask for an encoding this runtime cannot read back.
      pairsOut.push([k, key === "accept-encoding" && !zstd ? v0.replace(/\s*,?\s*zstd\b/gi, "").replace(/^\s*,\s*/, "") : v0]);
    }
    const socket = await this.openUpstream(host, port);
    let transport: Socket = socket;
    let version: "1.1" | "2" = "1.1";
    if (secure) {
      // The target gets the protocol the client used, when it supports it.
      const tls = tlsConnect({ socket, servername: /^[\d.]+$|:/.test(host) ? undefined : host, rejectUnauthorized: false, ALPNProtocols: req.version === "2" ? ["h2", "http/1.1"] : ["http/1.1"] });
      await new Promise<void>((resolve, reject) => {
        tls.once("secureConnect", () => resolve());
        tls.once("error", reject);
      });
      transport = tls;
      if (tls.alpnProtocol === "h2") version = "2";
    }
    if (version === "2") {
      const r = await sendH2(transport, req.url, req.method, pairsOut, req.body);
      return { status: r.status, statusText: "", headers: r.headers, version: "2", body: r.body };
    }
    const headers: OutgoingHttpHeaders = {};
    for (const [k, v] of pairsOut) {
      const prev = headers[k];
      headers[k] = prev === undefined ? v : Array.isArray(prev) ? [...prev, v] : [String(prev), v];
    }
    if (!pairsOut.some(([k]) => k.toLowerCase() === "host")) headers.Host = req.url.host;
    if (req.body.length || !["GET", "HEAD", "OPTIONS", "DELETE"].includes(req.method)) headers["Content-Length"] = String(req.body.length);
    return new Promise((resolve, reject) => {
      const send = secure ? httpsRequest : httpRequest;
      const r = send({
        host,
        port,
        method: req.method,
        path: `${req.url.pathname}${req.url.search}`,
        headers,
        // Without an agent, Node uses this connection (direct, or through the upstream proxy).
        createConnection: () => transport,
        rejectUnauthorized: false,
      });
      r.setTimeout(60_000, () => r.destroy(new Error("the server did not answer within 60 s")));
      r.once("response", (res) => {
        const base = { status: res.statusCode ?? 502, statusText: res.statusMessage ?? "", headers: pairs(res.rawHeaders), version: "1.1" as const };
        const length = Number(res.headers["content-length"]);
        const streaming = /text\/event-stream/i.test(String(res.headers["content-type"] ?? ""));
        if (streaming || length > MAX_BUFFERED_RESPONSE) return resolve({ ...base, stream: res });
        readBody(res, MAX_BUFFERED_RESPONSE).then(
          (body) => resolve({ ...base, body }),
          () => resolve({ ...base, stream: res }),
        );
      });
      r.once("error", reject);
      r.end(req.body);
    });
  }

  private reply(res: ServerResponse, status: number, message: string, url?: URL, block?: Block): void {
    if (res.headersSent) return void res.destroy();
    const html = `<!doctype html><meta charset="utf-8"><title>Penteos</title><body style="font-family:system-ui;background:#110e16;color:#eceaf1;padding:48px">
<div style="max-width:640px;margin:auto;border:1px solid #2d2738;border-radius:8px;padding:24px;background:#16131c">
<div style="color:#9d8cff;font-weight:600;margin-bottom:8px">Penteos</div>
<div style="font-size:18px;margin-bottom:8px">${status === 403 ? "Request blocked" : status === 499 ? "Request dropped" : "The request could not be completed"}</div>
<div style="color:#c3bfcd;line-height:1.5">${escapeHtml(message)}</div>
${url ? `<div style="margin-top:12px;color:#8d8799;font-family:monospace;word-break:break-all">${escapeHtml(url.href)}</div>` : ""}
</div></body>`;
    // The kind and host let the operator's browser offer a way out (see electron/browser/window.cjs).
    const extra: Record<string, string> = block ? { "X-Penteos-Block": block.kind, "X-Penteos-Host": encodeURIComponent(block.host), ...(block.detail ? { "X-Penteos-Detail": encodeURIComponent(block.detail.slice(0, 300)) } : {}) } : {};
    res.writeHead(status === 499 ? 418 : status, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Penteos": "blocked", ...extra });
    res.end(html);
  }

  // -------------------------------------------------------------------------------------------
  // WebSockets: the handshake is checked and recorded, then every message (both directions) is
  // read, recorded, offered to interception and forwarded. Compression is not negotiated, so
  // messages are plain and editable; untouched frames go out byte for byte.

  private async handleUpgrade(req: IncomingMessage, socket: Socket, head: Buffer, ctx: Ctx): Promise<void> {
    socket.on("error", () => socket.destroy());
    const started = Date.now();
    let engagement: Engagement;
    let url: URL;
    try {
      engagement = this.workspace.get(ctx.engagementId);
      url = this.urlOf(req, ctx);
    } catch {
      return void socket.destroy();
    }
    const preq: ProxyRequest = { method: req.method ?? "GET", url, headers: pairs(req.rawHeaders), body: Buffer.alloc(0) };
    const block = this.blockReason(engagement, url, ctx.source);
    if (block) {
      this.record(engagement, ctx, preq, undefined, { blocked: true, reason: block.reason, started, isStatic: false, inScope: false });
      return void socket.end(`HTTP/1.1 403 Forbidden\r\nX-Penteos: blocked\r\nX-Penteos-Block: ${block.kind}\r\n\r\n`);
    }
    const headers = preq.headers.filter(([k]) => !["proxy-authorization", "proxy-connection", "sec-websocket-extensions"].includes(k.toLowerCase()));
    const secure = url.protocol === "https:" || url.protocol === "wss:";
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const port = Number(url.port) || (secure ? 443 : 80);
    let up: Socket;
    try {
      const raw = await this.openUpstream(host, port);
      up = secure ? tlsConnect({ socket: raw, servername: /^[\d.]+$|:/.test(host) ? undefined : host, rejectUnauthorized: false, ALPNProtocols: ["http/1.1"] }) : raw;
      up.on("error", () => socket.destroy());
      socket.on("close", () => up.destroy());
      up.write(`${[`${preq.method} ${url.pathname}${url.search} HTTP/1.1`, ...headers.map(([k, v]) => `${k}: ${v}`)].join("\r\n")}\r\n\r\n`);
    } catch (e) {
      this.record(engagement, ctx, preq, undefined, { error: (e as Error).message, started, isStatic: false, inScope: true });
      return void socket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n${(e as Error).message}`);
    }

    let response: { head: Buffer; rest: Buffer };
    try {
      response = await readHead(up);
    } catch (e) {
      this.record(engagement, ctx, { ...preq, headers }, undefined, { error: (e as Error).message, started, isStatic: false, inScope: true });
      socket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n${(e as Error).message}`);
      return void up.destroy();
    }
    const lines = response.head.toString("latin1").split("\r\n");
    const m = /^HTTP\/[\d.]+\s+(\d{3})\s*(.*)$/.exec(lines[0] ?? "");
    const status = Number(m?.[1] ?? 502);
    const resHeaders = lines.slice(1).filter(Boolean).map((l) => [l.slice(0, l.indexOf(":")).trim(), l.slice(l.indexOf(":") + 1).trim()] as [string, string]);
    socket.write(response.head);
    const entryId = this.record(engagement, ctx, { ...preq, headers }, { status, statusText: m?.[2] ?? "", headers: resHeaders, body: Buffer.alloc(0) }, { started, isStatic: false, inScope: true, reason: "WebSocket" });

    if (status !== 101 || !entryId) {
      if (response.rest.length) socket.write(response.rest);
      up.pipe(socket);
      socket.pipe(up);
      return;
    }
    this.relayWs(engagement, url, entryId, socket, up, head, response.rest);
  }

  private relayWs(engagement: Engagement, url: URL, entryId: string, client: Socket, server: Socket, clientFirst: Buffer, serverFirst: Buffer): void {
    const wsUrl = url.href.replace(/^http/, "ws");
    const pump = (from: Socket, to: Socket, direction: "out" | "in", initial: Buffer) => {
      const reader = new FrameReader();
      const toServer = direction === "out";
      let chain: Promise<void> = Promise.resolve();
      let fragments: Buffer[] = [];
      let fragOpcode: number = OP.text;
      const fail = () => {
        from.destroy();
        to.destroy();
      };
      const handle = async (f: Frame) => {
        if (to.destroyed) return;
        if (f.opcode === OP.text || f.opcode === OP.binary) {
          if (!f.fin) {
            // A fragmented message: forwarded as it comes, recorded whole at the end.
            fragments = [f.payload];
            fragOpcode = f.opcode;
            to.write(f.raw);
            return;
          }
          const r = this.hooks.ws ? await this.hooks.ws(engagement, { url: wsUrl, direction, opcode: f.opcode, payload: f.payload }) : { payload: f.payload, opcode: f.opcode, edited: false };
          if (!r) {
            engagement.addWsMessage({ entryId, direction, opcode: f.opcode, payload: Buffer.concat([Buffer.from("[dropped by the operator] "), f.payload]), edited: true });
            return;
          }
          engagement.addWsMessage({ entryId, direction, opcode: r.opcode, payload: r.payload, edited: r.edited });
          to.write(r.edited ? encodeFrame(r.opcode, r.payload, toServer) : f.raw);
        } else if (f.opcode === OP.continuation) {
          fragments.push(f.payload);
          to.write(f.raw);
          if (f.fin) {
            engagement.addWsMessage({ entryId, direction, opcode: fragOpcode, payload: Buffer.concat(fragments) });
            fragments = [];
          }
        } else {
          to.write(f.raw);
          if (f.opcode === OP.close) {
            const code = f.payload.length >= 2 ? f.payload.readUInt16BE(0) : 1005;
            engagement.addWsMessage({ entryId, direction, opcode: OP.close, payload: Buffer.from(`[close ${code}] ${f.payload.subarray(2).toString("utf8")}`.trim()) });
          }
        }
      };
      const onData = (c: Buffer) => {
        let frames: Frame[];
        try {
          frames = reader.push(c);
        } catch {
          return fail();
        }
        for (const f of frames) chain = chain.then(() => handle(f)).catch(fail);
      };
      from.on("data", onData);
      from.on("end", () => void chain.then(() => to.end()));
      from.on("close", () => void chain.then(() => to.destroy()));
      if (initial.length) onData(initial);
      // The server side was paused after reading the handshake.
      from.resume();
    };
    pump(client, server, "out", clientFirst);
    pump(server, client, "in", serverFirst);
  }

  // -------------------------------------------------------------------------------------------
  // History and graph

  private record(
    engagement: Engagement,
    ctx: Ctx,
    req: ProxyRequest,
    res: ProxyResponse | undefined,
    meta: { started: number; held?: { ms: number }; isStatic: boolean; inScope: boolean; blocked?: boolean; reason?: string; error?: string; edited?: boolean; recordStatic?: boolean; streamedSize?: number },
  ): string | undefined {
    try {
      const mime = res?.headers.find(([k]) => k.toLowerCase() === "content-type")?.[1]?.split(";")[0]?.trim();
      const keepBody = !meta.isStatic || meta.recordStatic;
      let rawId: string | undefined;
      let requestLength: number | undefined;
      if (!meta.blocked) {
        const requestText = formatRequestText(req);
        requestLength = Buffer.byteLength(requestText);
        const exchange = `${requestText}\r\n\r\n${res ? formatResponseText(res, keepBody) : `[no response: ${meta.error ?? meta.reason ?? ""}]`}`;
        rawId = engagement.putRaw(exchange, { type: "http_exchange", mime: "message/http" });
      }
      const resSize = meta.streamedSize ?? res?.body.length ?? 0;
      const id = ulid();
      engagement.addProxyEntry({
        id,
        at: new Date(meta.started).toISOString(),
        source: ctx.source,
        method: req.method,
        url: req.url.href,
        host: req.url.host,
        path: `${req.url.pathname}${req.url.search}`,
        ...(res ? { status: res.status } : {}),
        ...(mime ? { mime } : {}),
        reqSize: req.body.length,
        resSize,
        durationMs: Date.now() - meta.started - (meta.held?.ms ?? 0),
        ...(meta.held && meta.held.ms >= 50 ? { heldMs: meta.held.ms } : {}),
        inScope: meta.inScope,
        blocked: Boolean(meta.blocked),
        ...(meta.reason ? { reason: meta.reason } : {}),
        ...(rawId ? { rawId } : {}),
        ...(requestLength !== undefined ? { requestLength } : {}),
        ...(req.version === "2" ? { httpVersion: "2" } : {}),
        ...(meta.error ? { error: meta.error } : {}),
        static: meta.isStatic || (mime ? BINARY_MIME.test(mime) : false),
        edited: Boolean(meta.edited),
      });
      // The application map: endpoints, methods, statuses, parameters (not for static files).
      if (res && meta.inScope && !meta.blocked && !meta.isStatic && res.status !== 101) {
        engagement.ingest(
          { format: INGEST_FORMAT, source: { parser: "proxy@0.1.0", tool: "proxy" }, rawIds: rawId ? [rawId] : [], observedAt: new Date().toISOString(), items: webItems(req, res) },
          this.options.actor,
        );
      }
      return id;
    } catch {
      // Recording must never break the browsing.
      return undefined;
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Helpers

/** Request headers as pairs; HTTP/2 pseudo-headers become a Host header. */
function requestHeaders(req: IncomingMessage): Array<[string, string]> {
  const all = pairs(req.rawHeaders);
  const out = all.filter(([k]) => !k.startsWith(":"));
  const authority = all.find(([k]) => k === ":authority")?.[1];
  if (authority && !out.some(([k]) => k.toLowerCase() === "host")) out.unshift(["Host", authority]);
  return out;
}

const H2_CONNECTION_HEADERS = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"]);

/** Response head for either protocol (HTTP/2 has no status text and lowercase, merged headers). */
function writeHead(res: ServerResponse, ctx: Ctx, status: number, statusText: string, headers: Array<[string, string]>): void {
  if (!ctx.h2) return void res.writeHead(status, statusText, headers.flat());
  const obj: Record<string, string | string[]> = {};
  for (const [k0, v] of headers) {
    const k = k0.toLowerCase();
    if (H2_CONNECTION_HEADERS.has(k)) continue;
    const prev = obj[k];
    obj[k] = prev === undefined ? v : Array.isArray(prev) ? [...prev, v] : [prev, v];
  }
  res.writeHead(status, obj);
}

/** Reads an HTTP response head (up to the blank line); what follows is returned apart. */
function readHead(socket: Socket, timeoutMs = 30_000): Promise<{ head: Buffer; rest: Buffer }> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => done(new Error("the server did not answer the handshake")), timeoutMs);
    const onData = (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      const i = buf.indexOf("\r\n\r\n");
      if (i >= 0) done(undefined, { head: buf.subarray(0, i + 4), rest: buf.subarray(i + 4) });
      else if (buf.length > 64 * 1024) done(new Error("headers too large"));
    };
    const onEnd = () => done(new Error("the server closed the connection"));
    const done = (err?: Error, value?: { head: Buffer; rest: Buffer }) => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("end", onEnd);
      socket.off("error", onErr);
      socket.pause();
      if (err) reject(err);
      else resolve(value!);
    };
    const onErr = (e: Error) => done(e);
    socket.on("data", onData);
    socket.once("end", onEnd);
    socket.once("error", onErr);
  });
}

/**
 * A socket-like stream over `socket` that first yields `first` (bytes already consumed). TLS and
 * the HTTP server read it through JavaScript, so nothing is lost. It answers the few socket
 * methods the HTTP server uses.
 */
function replay(socket: Socket, first: Buffer): Duplex {
  const d = new Duplex({
    read() {
      socket.resume();
    },
    write(chunk, encoding, cb) {
      socket.write(chunk, encoding, cb);
    },
    final(cb) {
      socket.end();
      cb();
    },
    destroy(err, cb) {
      socket.destroy(err ?? undefined);
      cb(err);
    },
  });
  d.push(first);
  socket.on("data", (c: Buffer) => {
    if (!d.push(c)) socket.pause();
  });
  socket.on("end", () => d.push(null));
  socket.on("error", (e) => d.destroy(e));
  socket.on("close", () => d.destroy());
  const shim = d as Duplex & Record<string, unknown>;
  shim.setTimeout = (ms: number, cb?: () => void) => (socket.setTimeout(ms, cb), d);
  shim.setNoDelay = (v?: boolean) => (socket.setNoDelay(v), d);
  shim.setKeepAlive = (v?: boolean, ms?: number) => (socket.setKeepAlive(v, ms), d);
  shim.ref = () => d;
  shim.unref = () => d;
  for (const k of ["remoteAddress", "remotePort", "remoteFamily", "localAddress", "localPort"] as const) Object.defineProperty(d, k, { get: () => socket[k] });
  return d;
}

function splitHostPort(target: string): [string, string] {
  const m = /^\[([^\]]+)\]:(\d+)$/.exec(target) ?? /^([^:]+):(\d+)$/.exec(target);
  return m ? [m[1]!, m[2]!] : [target, ""];
}

function pairs(raw: string[]): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (let i = 0; i < raw.length; i += 2) out.push([raw[i]!, raw[i + 1] ?? ""]);
  return out;
}

function readBody(stream: NodeJS.ReadableStream, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    stream.on("data", (c: Buffer) => {
      size += c.length;
      if (size > max) {
        reject(new Error(`more than ${Math.round(max / 1024 / 1024)} MB`));
        return;
      }
      chunks.push(c);
    });
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", reject);
  });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

/** The body decompressed (gzip, br, deflate), or undefined if it cannot be. */
export function decodeBody(body: Buffer, headers: Array<[string, string]>): Buffer | undefined {
  const enc = (headers.find(([k]) => k.toLowerCase() === "content-encoding")?.[1] ?? "").toLowerCase();
  try {
    if (enc.includes("gzip")) return gunzipSync(body);
    if (enc.includes("br")) return brotliDecompressSync(body);
    if (enc.includes("deflate")) return inflateSync(body);
    if (enc.includes("zstd")) return zstd ? zstd(body) : undefined;
    return body;
  } catch {
    return undefined;
  }
}

/** The body as text for the history: decompressed, binary left out, size-capped. */
export function bodyText(body: Buffer, headers: Array<[string, string]>, keep = true): string {
  if (!body.length) return "";
  const get = (name: string) => headers.find(([k]) => k.toLowerCase() === name)?.[1] ?? "";
  const mime = get("content-type");
  if (!keep || BINARY_MIME.test(mime)) return `[${mime || "content"} · ${body.length} bytes, not stored]`;
  let data = body;
  const enc = get("content-encoding").toLowerCase();
  try {
    if (enc.includes("gzip")) data = gunzipSync(body);
    else if (enc.includes("br")) data = brotliDecompressSync(body);
    else if (enc.includes("deflate")) data = inflateSync(body);
    else if (enc.includes("zstd")) {
      if (!zstd) return `[compressed (zstd) · ${body.length} bytes]`;
      data = zstd(body);
    }
  } catch {
    return `[compressed (${enc}) · ${body.length} bytes]`;
  }
  const text = data.subarray(0, MAX_RECORDED_BODY).toString("utf8");
  return data.length > MAX_RECORDED_BODY ? `${text}\n[… ${data.length - MAX_RECORDED_BODY} more bytes]` : text;
}

export function formatRequestText(req: ProxyRequest): string {
  const hasHost = req.headers.some(([k]) => k.toLowerCase() === "host");
  const headers = req.headers.filter(([k]) => k.toLowerCase() !== "proxy-authorization");
  return [`${req.method} ${req.url.pathname}${req.url.search} HTTP/${req.version === "2" ? "2" : "1.1"}`, ...(hasHost ? [] : [`Host: ${req.url.host}`]), ...headers.map(([k, v]) => `${k}: ${v}`), "", bodyText(req.body, req.headers)].join("\r\n");
}

export function formatResponseText(res: ProxyResponse, keepBody = true): string {
  return [`HTTP/${res.version === "2" ? "2" : "1.1"} ${res.status} ${res.statusText}`.trimEnd(), ...res.headers.map(([k, v]) => `${k}: ${v}`), "", bodyText(res.body, res.headers, keepBody)].join("\r\n");
}

function paramsOf(req: ProxyRequest): Array<{ name: string; location: "query" | "body" | "cookie" }> {
  const out: Array<{ name: string; location: "query" | "body" | "cookie" }> = [];
  for (const k of new Set(req.url.searchParams.keys())) out.push({ name: k, location: "query" });
  const ct = req.headers.find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "";
  const body = req.body.toString("utf8");
  if (body) {
    if (ct.includes("json")) {
      try {
        const j = JSON.parse(body) as unknown;
        if (j && typeof j === "object" && !Array.isArray(j)) for (const k of Object.keys(j)) out.push({ name: k, location: "body" });
      } catch {
        /* not JSON */
      }
    } else if (ct.includes("urlencoded")) for (const k of new Set(new URLSearchParams(body).keys())) out.push({ name: k, location: "body" });
  }
  return out;
}

export function webItems(req: ProxyRequest, res: ProxyResponse): IngestItem[] {
  const tech = res.headers.filter(([k]) => /^(server|x-powered-by)$/i.test(k)).map(([, v]) => ({ name: v.trim(), confidence: 0.9 }));
  const params = paramsOf(req);
  return [
    { op: "upsert", kind: "webapp", key: { origin: req.url.origin }, ...(tech.length ? { attributes: { technologies: tech } } : {}), confidence: 1 },
    {
      op: "upsert",
      kind: "endpoint",
      key: { origin: req.url.origin, path: req.url.pathname },
      attributes: { methods: [req.method], statusesSeen: [res.status], ...(params.length ? { params } : {}) },
      confidence: 1,
    },
  ] as IngestItem[];
}
