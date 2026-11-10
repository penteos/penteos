/**
 * Connection to the local core process. Everything the UI does goes through the operation
 * catalog - the same one agents use over MCP.
 */

export interface CoreEvent {
  type: string;
  id?: string;
  kind?: string;
  chunk?: string;
  [key: string]: unknown;
}

export class OperationFailure extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export type AgentEvent =
  | { kind: "user"; text: string; at: string; auto?: boolean; by?: string }
  | { kind: "notice"; text: string }
  | { kind: "delta"; text: string }
  | { kind: "text"; text: string }
  | { kind: "tool"; id: string; name: string; input: unknown; status: "running" | "ok" | "error"; summary?: string; approvalId?: string; runId?: string }
  | { kind: "status"; text: string }
  | { kind: "error"; text: string }
  | { kind: "card"; card: SalaCard }
  | { kind: "done"; provider: string; at: string };

/** A card in the Sala: what the verifier has to say. */
export interface SalaCard {
  type: "verdict";
  title: string;
  text: string;
  at: string;
  key?: string;
  findingId?: string;
  who?: string;
}

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void };
type TermHandlers = { data: (d: string) => void; exit: (code: number) => void };

export class CoreClient {
  private ws!: WebSocket;
  private seq = 0;
  private readonly pending = new Map<number, Pending>();
  private readonly listeners = new Set<(e: CoreEvent) => void>();
  private readonly statusListeners = new Set<(s: boolean) => void>();
  private readonly switchListeners = new Set<() => void>();
  private readonly agentListeners = new Set<(e: AgentEvent | { kind: "reset" }) => void>();
  private readonly subagentListeners = new Set<(key: string, e: AgentEvent) => void>();
  private readonly refs = new Map<string, (m: Record<string, unknown>) => void>();
  private readonly terms = new Map<string, TermHandlers>();
  private readonly termOpens = new Map<string, (id: string) => void>();
  private queue: string[] = [];
  connected = false;
  termDenied: string | undefined;

  /** Who this window is connected as, and whether the core is a team server. */
  me: { id: string; name: string; role: string } | undefined;
  teamMode = false;
  online: Array<{ id: string; name: string; role: string }> = [];
  private readonly presenceListeners = new Set<() => void>();

  constructor(
    /** Local core port, or a team server URL (http(s)://host:port). */
    private readonly endpoint: string,
    private readonly token: string,
  ) {
    this.connect();
  }

  /** Where the core answers HTTP (plugin panels are served from there, on their own origin). */
  get httpBase(): string {
    return this.remote ? this.endpoint.replace(/\/$/, "") : `http://127.0.0.1:${this.endpoint}`;
  }

  get remote(): boolean {
    return /^https?:\/\//.test(this.endpoint);
  }

  private wsUrl(): string {
    const base = this.remote ? this.endpoint.replace(/^http/, "ws") : `ws://127.0.0.1:${this.endpoint}`;
    return `${base}/v0/ws`;
  }

  onPresence(listener: () => void): () => void {
    this.presenceListeners.add(listener);
    return () => this.presenceListeners.delete(listener);
  }

  private connect() {
    // The token rides in the WebSocket protocol header, never in the URL (proxies and logs keep URLs).
    this.ws = new WebSocket(this.wsUrl(), ["penteos", `penteos.token.${this.token}`]);
    this.ws.onopen = () => {
      this.connected = true;
      for (const m of this.queue) this.ws.send(m);
      this.queue = [];
      for (const l of this.statusListeners) l(true);
    };
    this.ws.onclose = () => {
      this.connected = false;
      for (const l of this.statusListeners) l(false);
      setTimeout(() => this.connect(), 1000);
    };
    this.ws.onmessage = (msg) => {
      const m = JSON.parse(String(msg.data)) as Record<string, unknown>;
      if (typeof m.ref === "string" && this.refs.has(m.ref)) {
        this.refs.get(m.ref)!(m);
        this.refs.delete(m.ref);
        if (m.t !== "term.opened") return;
      }
      switch (m.t) {
        case "hello":
          this.me = m.you as typeof this.me;
          this.teamMode = Boolean(m.teamMode);
          for (const l of this.presenceListeners) l();
          break;
        case "presence":
          this.online = m.operators as typeof this.online;
          for (const l of this.presenceListeners) l();
          break;
        case "term.denied":
          this.termDenied = String(m.reason);
          this.termOpens.get(m.ref as string)?.("");
          this.termOpens.delete(m.ref as string);
          break;
        case "agent.event":
          for (const l of this.agentListeners) l(m.event as AgentEvent);
          break;
        case "subagent.event":
          for (const l of this.subagentListeners) l(String(m.key), m.event as AgentEvent);
          break;
        case "agent.reset":
          for (const l of this.agentListeners) l({ kind: "reset" });
          break;
        case "result": {
          const p = this.pending.get(m.id as number);
          if (!p) return;
          this.pending.delete(m.id as number);
          if (m.ok) p.resolve(m.result);
          else {
            const err = m.error as { code: string; message: string };
            p.reject(new OperationFailure(err.code, err.message));
          }
          break;
        }
        case "event": {
          for (const l of this.listeners) l(m.event as CoreEvent);
          const ev = m.event as { type: string; dir?: string };
          if (ev.type === "engagement.switched") for (const l of this.switchListeners) l();
          if (ev.type === "activate.failed") window.dispatchEvent(new CustomEvent("penteos:activate-failed", { detail: ev }));
          break;
        }
        case "chatgpt.done":
          // Sign in with ChatGPT finished in the browser: the provider screens refresh.
          window.dispatchEvent(new CustomEvent("penteos:chatgpt-done", { detail: { ok: Boolean(m.ok), error: m.error } }));
          break;
        case "term.opened":
          this.termOpens.get(m.ref as string)?.(m.termId as string);
          this.termOpens.delete(m.ref as string);
          break;
        case "term.data":
          this.terms.get(m.termId as string)?.data(m.data as string);
          break;
        case "term.exit":
          this.terms.get(m.termId as string)?.exit(m.code as number);
          break;
      }
    };
  }

  private send(message: unknown) {
    const text = JSON.stringify(message);
    if (this.connected) this.ws.send(text);
    else this.queue.push(text);
  }

  call<T = unknown>(op: string, input: unknown = {}): Promise<T> {
    const id = ++this.seq;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      this.send({ t: "call", id, op, input });
    });
  }

  onEvent(listener: (e: CoreEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Sends a message that the core answers with the same `ref`. */
  request<T>(t: string, payload: { [key: string]: unknown } = {}): Promise<T> {
    const ref = `q${++this.seq}`;
    return new Promise<T>((resolve) => {
      this.refs.set(ref, (m) => resolve(m as T));
      this.send({ t, ref, ...payload });
    });
  }

  notify(t: string, payload: Record<string, unknown> = {}) {
    this.send({ t, ...payload });
  }

  /** Events of the agents that run alongside the Maestro (the verifier), by job key. */
  onSubagentEvent(listener: (key: string, e: AgentEvent) => void): () => void {
    this.subagentListeners.add(listener);
    return () => this.subagentListeners.delete(listener);
  }

  onAgentEvent(listener: (e: AgentEvent | { kind: "reset" }) => void): () => void {
    this.agentListeners.add(listener);
    return () => this.agentListeners.delete(listener);
  }

  /** Makes another engagement the active one, for this window and the integrated terminal. */
  activate(engagementId: string) {
    this.send({ t: "activate", engagementId });
  }

  onEngagementSwitch(listener: () => void): () => void {
    this.switchListeners.add(listener);
    return () => this.switchListeners.delete(listener);
  }

  onStatus(listener: (connected: boolean) => void): () => void {
    this.statusListeners.add(listener);
    return () => this.statusListeners.delete(listener);
  }

  openTerminal(cols: number, rows: number, handlers: TermHandlers): Promise<string> {
    const ref = `r${++this.seq}`;
    return new Promise((resolve) => {
      this.termOpens.set(ref, (id) => {
        if (id) this.terms.set(id, handlers);
        resolve(id);
      });
      this.send({ t: "term.open", ref, cols, rows });
    });
  }

  termInput(termId: string, data: string) {
    this.send({ t: "term.input", termId, data });
  }

  termResize(termId: string, cols: number, rows: number) {
    this.send({ t: "term.resize", termId, cols, rows });
  }

  termClose(termId: string) {
    this.terms.delete(termId);
    this.send({ t: "term.close", termId });
  }
}
