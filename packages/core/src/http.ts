import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as http2Connect } from "node:http2";
import type { Socket } from "node:net";
import type { Duplex } from "node:stream";
import { connect as tlsConnect, type TLSSocket } from "node:tls";

/**
 * Raw HTTP requests, as a pentester writes them in a Repeater:
 *
 *   POST /login.php HTTP/1.1
 *   Host: example.com
 *   Content-Type: application/x-www-form-urlencoded
 *
 *   username=admin&password=x
 *
 * Sent exactly as written (no redirects followed, any certificate accepted - targets often use
 * self-signed ones), and kept as a raw exchange that can become evidence.
 */

export interface RawRequest {
  method: string;
  path: string;
  headers: Array<[string, string]>;
  body: string;
  /** "HTTP/2" in the request line asks for HTTP/2; anything else is HTTP/1.1. */
  version?: "1.1" | "2";
}

export interface HttpResponse {
  version?: "1.1" | "2";
  status: number;
  statusText: string;
  headers: Array<[string, string]>;
  body: string;
  timeMs: number;
  size: number;
}

export function parseRawRequest(raw: string): RawRequest {
  const text = raw.replace(/\r\n/g, "\n");
  const split = text.indexOf("\n\n");
  const head = split === -1 ? text : text.slice(0, split);
  const body = split === -1 ? "" : text.slice(split + 2);
  const [first, ...lines] = head.split("\n");
  const m = /^([A-Z]+)\s+(\S+)(?:\s+HTTP\/([\d.]+))?\s*$/i.exec(first?.trim() ?? "");
  if (!m) throw new Error('the first line must be "METHOD /path HTTP/1.1"');
  const version = m[3] === "2" || m[3] === "2.0" ? ("2" as const) : ("1.1" as const);
  const headers: Array<[string, string]> = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    const i = line.indexOf(":");
    if (i <= 0) throw new Error(`invalid header line: ${line}`);
    headers.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
  }
  return { method: m[1]!.toUpperCase(), path: m[2]!, headers, body, version };
}

/** The URL a raw request goes to: absolute paths in the request line win over the origin. */
export function requestUrl(origin: string, req: RawRequest): URL {
  if (/^https?:\/\//i.test(req.path)) return new URL(req.path);
  return new URL(req.path, origin.endsWith("/") ? origin : `${origin}/`);
}

export function formatRequest(req: RawRequest, url: URL): string {
  const headers = req.headers.some(([k]) => k.toLowerCase() === "host") ? req.headers : [["Host", url.host] as [string, string], ...req.headers];
  return [`${req.method} ${url.pathname}${url.search} HTTP/${req.version === "2" ? "2" : "1.1"}`, ...headers.map(([k, v]) => `${k}: ${v}`), "", req.body].join("\r\n");
}

export function formatResponse(res: HttpResponse): string {
  return [`HTTP/${res.version === "2" ? "2" : "1.1"} ${res.status} ${res.statusText}`.trimEnd(), ...res.headers.map(([k, v]) => `${k}: ${v}`), "", res.body].join("\r\n");
}

/** Headers that only make sense hop by hop in HTTP/1.1; HTTP/2 forbids them. */
const H2_FORBIDDEN = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host", "content-length"]);

/** An HTTP/1-style request turned into HTTP/2 headers (pseudo-headers first, lowercase names). */
export function h2Headers(method: string, url: URL, headers: Array<[string, string]>, bodyLength: number): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {
    ":method": method,
    ":path": `${url.pathname}${url.search}`,
    ":scheme": url.protocol.replace(":", ""),
    ":authority": headers.find(([k]) => k.toLowerCase() === "host")?.[1] ?? url.host,
  };
  for (const [k0, v] of headers) {
    const k = k0.toLowerCase();
    if (H2_FORBIDDEN.has(k) || k.startsWith(":")) continue;
    if (k === "te" && v.toLowerCase() !== "trailers") continue;
    const prev = out[k];
    out[k] = prev === undefined ? v : Array.isArray(prev) ? [...prev, v] : [prev, v];
  }
  if (bodyLength || !["GET", "HEAD", "OPTIONS"].includes(method)) out["content-length"] = String(bodyLength);
  return out;
}

/** Sends one request over HTTP/2 on an already negotiated TLS socket (ALPN "h2"). */
export function sendH2(socket: TLSSocket | Socket, url: URL, method: string, headers: Array<[string, string]>, body: Buffer, timeoutMs = 60_000): Promise<{ status: number; headers: Array<[string, string]>; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const session = http2Connect(url.origin, { createConnection: () => socket as unknown as Duplex });
    const fail = (e: Error) => {
      session.destroy();
      reject(e);
    };
    session.on("error", fail);
    const stream = session.request(h2Headers(method, url, headers, body.length), { endStream: body.length === 0 });
    stream.setTimeout(timeoutMs, () => fail(new Error(`the server did not answer within ${Math.round(timeoutMs / 1000)} s`)));
    let status = 0;
    const resHeaders: Array<[string, string]> = [];
    stream.on("response", (h) => {
      status = Number(h[":status"] ?? 0);
      for (const [k, v] of Object.entries(h)) {
        if (k.startsWith(":") || v === undefined) continue;
        for (const x of Array.isArray(v) ? v : [v]) resHeaders.push([k, String(x)]);
      }
    });
    const chunks: Buffer[] = [];
    stream.on("data", (c: Buffer) => chunks.push(c));
    stream.on("end", () => {
      session.close();
      resolve({ status, headers: resHeaders, body: Buffer.concat(chunks) });
    });
    stream.on("error", fail);
    if (body.length) stream.end(body);
  });
}

const MAX_BODY = 5 * 1024 * 1024;

export function sendHttp(url: URL, req: RawRequest, timeoutMs = 30_000): Promise<HttpResponse> {
  const started = Date.now();
  if (req.version === "2") return sendHttp2(url, req, timeoutMs, started);
  const send = url.protocol === "https:" ? httpsRequest : httpRequest;
  const headers: Record<string, string | string[]> = {};
  for (const [k, v] of req.headers) {
    // Recomputed for the body actually sent.
    if (k.toLowerCase() === "content-length") continue;
    const prev = headers[k];
    headers[k] = prev === undefined ? v : Array.isArray(prev) ? [...prev, v] : [prev, v];
  }
  if (!Object.keys(headers).some((k) => k.toLowerCase() === "host")) headers.Host = url.host;
  const body = Buffer.from(req.body, "utf8");
  if (body.length || !["GET", "HEAD", "OPTIONS"].includes(req.method)) headers["Content-Length"] = String(body.length);

  return new Promise((resolve, reject) => {
    const r = send(
      url,
      { method: req.method, headers, rejectUnauthorized: false, timeout: timeoutMs },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size <= MAX_BODY) chunks.push(c);
        });
        res.on("end", () => {
          const raw = res.rawHeaders;
          const pairs: Array<[string, string]> = [];
          for (let i = 0; i < raw.length; i += 2) pairs.push([raw[i]!, raw[i + 1]!]);
          resolve({
            status: res.statusCode ?? 0,
            statusText: res.statusMessage ?? "",
            headers: pairs,
            body: Buffer.concat(chunks).toString("utf8") + (size > MAX_BODY ? `\n[… ${size - MAX_BODY} more bytes not stored]` : ""),
            timeMs: Date.now() - started,
            size,
          });
        });
        res.on("error", reject);
      },
    );
    r.on("timeout", () => r.destroy(new Error(`no response after ${Math.round(timeoutMs / 1000)}s`)));
    r.on("error", reject);
    if (body.length) r.write(body);
    r.end();
  });
}

/** Parameter names seen in a request: query string, form or JSON body, cookies. */
export function paramsOf(url: URL, req: RawRequest): Array<{ name: string; location: "query" | "body" | "cookie" }> {
  const out: Array<{ name: string; location: "query" | "body" | "cookie" }> = [];
  for (const k of new Set(url.searchParams.keys())) out.push({ name: k, location: "query" });
  const ct = req.headers.find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "";
  if (req.body) {
    if (ct.includes("json")) {
      try {
        const j = JSON.parse(req.body) as unknown;
        if (j && typeof j === "object" && !Array.isArray(j)) for (const k of Object.keys(j)) out.push({ name: k, location: "body" });
      } catch {
        /* not JSON after all */
      }
    } else if (!ct || ct.includes("urlencoded")) {
      for (const k of new Set(new URLSearchParams(req.body).keys())) out.push({ name: k, location: "body" });
    }
  }
  return out;
}

/** HTTP/2 on purpose (the request line said HTTP/2): TLS with ALPN, or an error if the server does not speak it. */
function sendHttp2(url: URL, req: RawRequest, timeoutMs: number, started: number): Promise<HttpResponse> {
  if (url.protocol !== "https:") return Promise.reject(new Error("HTTP/2 is only used over HTTPS (h2): change the URL to https:// or the line to HTTP/1.1"));
  const host = url.hostname.replace(/^\[|\]$/g, "");
  return new Promise((resolve, reject) => {
    // Both offered, so a server without HTTP/2 answers with a clear choice instead of a TLS alert.
    const socket = tlsConnect({ host, port: Number(url.port) || 443, servername: /^[\d.]+$|:/.test(host) ? undefined : host, ALPNProtocols: ["h2", "http/1.1"], rejectUnauthorized: false });
    socket.setTimeout(timeoutMs, () => socket.destroy(new Error(`no TCP connection after ${Math.round(timeoutMs / 1000)} s (a firewall dropping this machine's traffic, or the host is down)`)));
    socket.once("error", reject);
    socket.once("secureConnect", () => {
      if (socket.alpnProtocol !== "h2") {
        socket.destroy();
        return reject(new Error("the server does not speak HTTP/2 (h2 not accepted): use HTTP/1.1 on the first line"));
      }
      socket.setTimeout(0);
      const body = Buffer.from(req.body, "utf8");
      sendH2(socket, url, req.method, req.headers, body, timeoutMs).then(
        (r) =>
          resolve({
            version: "2",
            status: r.status,
            statusText: "",
            headers: r.headers,
            body: r.body.subarray(0, MAX_BODY).toString("utf8") + (r.body.length > MAX_BODY ? `\n[… ${r.body.length - MAX_BODY} more bytes not stored]` : ""),
            timeMs: Date.now() - started,
            size: r.body.length,
          }),
        reject,
      );
    });
  });
}
