import { randomBytes } from "node:crypto";
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { connect, type Socket } from "node:net";

/**
 * The egress proxy of free plugins. A free plugin runs with
 * this proxy as its way out (HTTP_PROXY/HTTPS_PROXY; Node, Python, curl and most tools honor it):
 * every connection is seen - which plugin, which host, when - and passed on. It never blocks:
 * Penteos watches and warns, the operator decides. HTTPS is tunneled (CONNECT) without decrypting
 * it; plain HTTP bodies can be read for what they carry.
 */

export interface EgressEvent {
  pluginId?: string;
  host: string;
  port: number;
  kind: "connect" | "http";
  method?: string;
  url?: string;
  /** The start of a plain HTTP request body (to look for the client's data). */
  body?: Buffer;
}

const MAX_BODY_PEEK = 64 * 1024;

export class EgressProxy {
  private server: Server | undefined;
  private port = 0;
  private readonly tokens = new Map<string, string>();
  private readonly listeners = new Set<(e: EgressEvent) => void>();

  async start(): Promise<number> {
    if (this.server) return this.port;
    const server = createServer((req, res) => this.forward(req, res));
    server.on("connect", (req, socket, head) => this.tunnel(req, socket as Socket, head));
    server.on("clientError", (_e, socket) => socket.destroy());
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    this.server = server;
    this.port = (server.address() as { port: number }).port;
    return this.port;
  }

  stop(): void {
    this.server?.close();
    this.server = undefined;
  }

  onConnection(listener: (e: EgressEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** The environment that sends a plugin's traffic through here, tagged with its id. */
  env(pluginId: string): Record<string, string> {
    if (!this.server) return {};
    let token = this.tokens.get(pluginId);
    if (!token) this.tokens.set(pluginId, (token = randomBytes(12).toString("hex")));
    const url = `http://${encodeURIComponent(pluginId)}:${token}@127.0.0.1:${this.port}`;
    return { HTTP_PROXY: url, HTTPS_PROXY: url, http_proxy: url, https_proxy: url, NO_PROXY: "", no_proxy: "", NODE_USE_ENV_PROXY: "1", PENTEOS_EGRESS_PROXY: url };
  }

  get address(): string | undefined {
    return this.server ? `127.0.0.1:${this.port}` : undefined;
  }

  /** Which plugin a request comes from (its credentials in the proxy URL). */
  private who(req: IncomingMessage): string | undefined {
    const auth = req.headers["proxy-authorization"];
    if (typeof auth !== "string" || !auth.startsWith("Basic ")) return undefined;
    const [id, token] = Buffer.from(auth.slice(6), "base64").toString("utf8").split(":");
    const plugin = decodeURIComponent(id ?? "");
    return plugin && this.tokens.get(plugin) === token ? plugin : undefined;
  }

  private emit(e: EgressEvent): void {
    for (const l of this.listeners) {
      try {
        l(e);
      } catch {
        /* a listener never breaks the traffic */
      }
    }
  }

  private tunnel(req: IncomingMessage, client: Socket, head: Buffer): void {
    const [host, portText] = (req.url ?? "").split(/:(?=\d+$)/);
    const port = Number(portText) || 443;
    if (!host) {
      client.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      return;
    }
    const pluginId = this.who(req);
    this.emit({ ...(pluginId ? { pluginId } : {}), host: host.replace(/^\[|\]$/g, ""), port, kind: "connect" });
    const upstream = connect(port, host.replace(/^\[|\]$/g, ""), () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    const close = () => {
      upstream.destroy();
      client.destroy();
    };
    upstream.on("error", () => {
      if (client.writable) client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      close();
    });
    client.on("error", close);
  }

  private forward(req: IncomingMessage, res: ServerResponse): void {
    let target: URL;
    try {
      target = new URL(req.url ?? "");
    } catch {
      res.writeHead(400).end();
      return;
    }
    const pluginId = this.who(req);
    const chunks: Buffer[] = [];
    let peeked = 0;
    const headers = { ...req.headers };
    delete headers["proxy-authorization"];
    delete headers["proxy-connection"];
    const upstream = httpRequest(target, { method: req.method, headers }, (up) => {
      res.writeHead(up.statusCode ?? 502, up.headers);
      up.pipe(res);
    });
    upstream.on("error", () => {
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    req.on("data", (c: Buffer) => {
      if (peeked < MAX_BODY_PEEK) {
        chunks.push(c.subarray(0, MAX_BODY_PEEK - peeked));
        peeked += c.length;
      }
    });
    req.on("end", () =>
      this.emit({ ...(pluginId ? { pluginId } : {}), host: target.hostname, port: Number(target.port) || 80, kind: "http", method: req.method ?? "GET", url: target.toString(), ...(chunks.length ? { body: Buffer.concat(chunks) } : {}) }),
    );
    req.pipe(upstream);
  }
}
