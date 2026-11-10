import WebSocket from "ws";

/**
 * A minimal Chrome DevTools Protocol client: commands with replies, events, and flat sessions
 * (one per page). Enough to drive a headless Chromium without pulling a browser library.
 */

type Listener = (params: Record<string, unknown>, sessionId?: string) => void;

export class Cdp {
  private nextId = 1;
  private readonly pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private readonly listeners = new Map<string, Set<Listener>>();
  private closed = false;

  private constructor(private readonly ws: WebSocket) {
    ws.on("message", (data) => {
      let msg: { id?: number; result?: unknown; error?: { message: string }; method?: string; params?: Record<string, unknown>; sessionId?: string };
      try {
        msg = JSON.parse(String(data));
      } catch {
        return;
      }
      if (msg.id !== undefined) {
        const p = this.pending.get(msg.id);
        if (!p) return;
        this.pending.delete(msg.id);
        if (msg.error) p.reject(new Error(msg.error.message));
        else p.resolve(msg.result ?? {});
        return;
      }
      if (msg.method) for (const l of this.listeners.get(msg.method) ?? []) l(msg.params ?? {}, msg.sessionId);
    });
    ws.on("close", () => {
      this.closed = true;
      for (const p of this.pending.values()) p.reject(new Error("the browser closed"));
      this.pending.clear();
    });
  }

  static connect(url: string, timeoutMs = 10_000): Promise<Cdp> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url, { perMessageDeflate: false, maxPayload: 256 * 1024 * 1024 });
      const timer = setTimeout(() => {
        ws.terminate();
        reject(new Error("could not connect to the browser"));
      }, timeoutMs);
      ws.once("open", () => {
        clearTimeout(timer);
        resolve(new Cdp(ws));
      });
      ws.once("error", (e) => {
        clearTimeout(timer);
        reject(e);
      });
    });
  }

  get isClosed(): boolean {
    return this.closed;
  }

  send<T = Record<string, unknown>>(method: string, params: Record<string, unknown> = {}, sessionId?: string, timeoutMs = 30_000): Promise<T> {
    if (this.closed) return Promise.reject(new Error("the browser closed"));
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v as T);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }

  on(method: string, listener: Listener): () => void {
    const set = this.listeners.get(method) ?? new Set();
    set.add(listener);
    this.listeners.set(method, set);
    return () => set.delete(listener);
  }

  close(): void {
    this.closed = true;
    try {
      this.ws.close();
    } catch {
      /* already closed */
    }
  }
}
