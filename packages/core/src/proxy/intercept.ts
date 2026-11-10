import { ulid } from "@penteos/schema";
import { EventEmitter } from "node:events";
import type { Engagement } from "../engagement.js";
import { decodeBody, type ProxyRequest, type ProxyResponse } from "./server.js";

/**
 * Stage 2 of the proxy: replace rules (applied to all traffic) and interception (a message
 * waits until the operator forwards it - edited or not - or drops it).
 *
 * Safety rules:
 *  - a message the operator did not change is forwarded byte for byte (binary uploads,
 *    compressed bodies and odd encodings survive untouched);
 *  - a waiting message is released unchanged after a timeout, and all are released when
 *    interception is turned off or the core stops, so the browser never hangs forever;
 *  - an edited request is checked against the scope again before it leaves.
 */

export interface ReplaceRule {
  id: string;
  enabled: boolean;
  /** Where it applies. */
  target: "request_header" | "request_body" | "request_url" | "response_header" | "response_body";
  /** Text or regular expression to find. Empty + a header target: add `replace` as a new header line. */
  match: string;
  regex: boolean;
  /** Replacement ($1… for regex groups). Empty on a header line: removes the line. */
  replace: string;
  comment?: string;
}

export interface InterceptSettings {
  requests: boolean;
  responses: boolean;
  /** WebSocket messages, both directions. */
  wsMessages: boolean;
  inScopeOnly: boolean;
  skipStatic: boolean;
  /** Only hosts containing this text (empty: all). */
  hostContains: string;
  methods: string[];
  /** Who set it last: an agent never cuts short what the operator may be editing. */
  by?: "human" | "agent";
}

export const DEFAULT_INTERCEPT: InterceptSettings = { requests: false, responses: false, wsMessages: false, inScopeOnly: true, skipStatic: true, hostContains: "", methods: [] };

export interface PendingMessage {
  id: string;
  kind: "request" | "response" | "ws_out" | "ws_in";
  engagementId: string;
  createdAt: string;
  method: string;
  url: string;
  status?: number;
  /** What the operator sees and edits. */
  raw: string;
  /** The body could not be shown as text: if left as is, the original bytes go out. */
  binaryBody: boolean;
}

type Decision = { action: "forward"; raw?: string } | { action: "drop" };

const STATIC = /\.(png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|css|js|mjs|map|mp4|webm|mp3|wav|ogg|pdf|zip)$/i;
const TIMEOUT_MS = 10 * 60 * 1000;
/** Waiting this long means nobody is looking at the queue: whoever drives the project is told. */
const STALL_MS = 15_000;

function header(headers: Array<[string, string]>, name: string): string {
  return headers.find(([k]) => k.toLowerCase() === name)?.[1] ?? "";
}

/** Bodies editable as text: not binary, not huge (editing a cut body would corrupt it). */
const MAX_EDITABLE = 2 * 1024 * 1024;
function isTextual(headers: Array<[string, string]>, body: Buffer): boolean {
  if (!body.length) return true;
  if (body.length > MAX_EDITABLE) return false;
  const ct = header(headers, "content-type").toLowerCase();
  if (/^(image|audio|video|font)\/|octet-stream|zip|pdf|protobuf|multipart\/form-data/.test(ct)) return false;
  return true;
}

// ---------------------------------------------------------------------------------------------
// Replace rules

function applyText(rule: ReplaceRule, text: string): string {
  if (rule.regex) {
    try {
      return text.replace(new RegExp(rule.match, "g"), rule.replace);
    } catch {
      return text; // an invalid regex never breaks traffic (it is validated when saved)
    }
  }
  return rule.match ? text.split(rule.match).join(rule.replace) : text;
}

function applyHeaders(rule: ReplaceRule, headers: Array<[string, string]>): Array<[string, string]> {
  if (!rule.match && rule.replace.includes(":")) {
    const i = rule.replace.indexOf(":");
    return [...headers, [rule.replace.slice(0, i).trim(), rule.replace.slice(i + 1).trim()]];
  }
  const out: Array<[string, string]> = [];
  for (const [k, v] of headers) {
    const line = applyText(rule, `${k}: ${v}`);
    if (!line.trim()) continue; // replaced with nothing: the header goes away
    const i = line.indexOf(":");
    out.push(i > 0 ? [line.slice(0, i).trim(), line.slice(i + 1).trim()] : [k, v]);
  }
  return out;
}

const RULE_TARGET: Record<ReplaceRule["target"], string> = { request_header: "request header", request_body: "request body", request_url: "URL", response_header: "response header", response_body: "response body" };

/** One line for agents and logs: what the rule does (the interface describes rules itself). */
export function describeRule(r: ReplaceRule): string {
  const where = RULE_TARGET[r.target];
  if (!r.match && r.target.endsWith("header")) return `add "${r.replace}" (${where})`;
  if (!r.replace) return `remove "${r.match}" (${where})`;
  return `"${r.match}" → "${r.replace}" (${where}${r.regex ? ", regex" : ""})`;
}

export function validateRule(rule: ReplaceRule): string | undefined {
  if (rule.regex) {
    try {
      new RegExp(rule.match, "g");
    } catch (e) {
      return `invalid regex: ${(e as Error).message}`;
    }
  }
  if (!rule.match && !(rule.target.endsWith("header") && rule.replace.includes(":"))) return "the text to look for is missing";
  return undefined;
}

export function applyRequestRules(rules: ReplaceRule[], req: ProxyRequest): { req: ProxyRequest; edited: boolean } {
  let out = req;
  let edited = false;
  for (const r of rules.filter((x) => x.enabled && x.target.startsWith("request"))) {
    if (r.target === "request_url") {
      const next = applyText(r, out.url.href);
      if (next !== out.url.href) {
        try {
          out = { ...out, url: new URL(next) };
          edited = true;
        } catch {
          /* the result is not a URL: ignore the rule */
        }
      }
    } else if (r.target === "request_header") {
      const next = applyHeaders(r, out.headers);
      if (JSON.stringify(next) !== JSON.stringify(out.headers)) (out = { ...out, headers: next }), (edited = true);
    } else if (r.target === "request_body" && isTextual(out.headers, out.body)) {
      const text = out.body.toString("utf8");
      const next = applyText(r, text);
      if (next !== text) (out = { ...out, body: Buffer.from(next, "utf8") }), (edited = true);
    }
  }
  return { req: out, edited };
}

export function applyResponseRules(rules: ReplaceRule[], res: ProxyResponse): { res: ProxyResponse; edited: boolean } {
  let out = res;
  let edited = false;
  for (const r of rules.filter((x) => x.enabled && x.target.startsWith("response"))) {
    if (r.target === "response_header") {
      const next = applyHeaders(r, out.headers);
      if (JSON.stringify(next) !== JSON.stringify(out.headers)) (out = { ...out, headers: next }), (edited = true);
    } else if (r.target === "response_body" && isTextual(out.headers, out.body)) {
      const text = decodedBody(out);
      if (text === undefined) continue;
      const next = applyText(r, text);
      if (next !== text) (out = withTextBody(out, next)), (edited = true);
    }
  }
  return { res: out, edited };
}

/** Response body as text (decompressed); undefined when it cannot be decompressed. */
function decodedBody(res: ProxyResponse): string | undefined {
  const d = decodeBody(res.body, res.headers);
  return d && d.length <= MAX_EDITABLE ? d.toString("utf8") : undefined;
}

/** A response with a new text body: no longer compressed, length recomputed on the way out. */
function withTextBody(res: ProxyResponse, text: string): ProxyResponse {
  return { ...res, headers: res.headers.filter(([k]) => k.toLowerCase() !== "content-encoding"), body: Buffer.from(text, "utf8") };
}

// ---------------------------------------------------------------------------------------------
// Interception

function requestRaw(req: ProxyRequest): { raw: string; binary: boolean } {
  const binary = !isTextual(req.headers, req.body);
  const hasHost = req.headers.some(([k]) => k.toLowerCase() === "host");
  // Headers between the browser and the proxy only: they never reach the target anyway.
  const internal = new Set(["proxy-authorization", "proxy-connection"]);
  const lines = [`${req.method} ${req.url.pathname}${req.url.search} HTTP/1.1`, ...(hasHost ? [] : [`Host: ${req.url.host}`]), ...req.headers.filter(([k]) => !internal.has(k.toLowerCase())).map(([k, v]) => `${k}: ${v}`)];
  return { raw: `${lines.join("\n")}\n\n${binary ? `[binary body: ${req.body.length} bytes; sent unchanged unless edited]` : req.body.toString("utf8")}`, binary };
}

function responseRaw(res: ProxyResponse): { raw: string; binary: boolean } {
  const text = isTextual(res.headers, res.body) ? decodedBody(res) : undefined;
  const binary = text === undefined;
  return {
    raw: `${[`HTTP/1.1 ${res.status} ${res.statusText}`, ...res.headers.map(([k, v]) => `${k}: ${v}`)].join("\n")}\n\n${binary ? `[binary or compressed body: ${res.body.length} bytes; sent unchanged unless edited]` : text}`,
    binary,
  };
}

function splitRaw(raw: string): { head: string[]; body: string } {
  const text = raw.replace(/\r\n/g, "\n");
  const cut = text.indexOf("\n\n");
  const head = (cut === -1 ? text : text.slice(0, cut)).split("\n").filter((l) => l.trim());
  return { head, body: cut === -1 ? "" : text.slice(cut + 2) };
}

function parseHeaders(lines: string[]): Array<[string, string]> {
  return lines.flatMap((l) => {
    const i = l.indexOf(":");
    return i > 0 ? [[l.slice(0, i).trim(), l.slice(i + 1).trim()] as [string, string]] : [];
  });
}

/** The operator's text back into a request. Throws with a readable message if malformed. */
export function editedRequest(original: ProxyRequest, raw: string, binaryPlaceholder: string | undefined): ProxyRequest {
  const { head, body } = splitRaw(raw);
  const m = /^([A-Za-z]+)\s+(\S+)(?:\s+HTTP\/[\d.]+)?$/.exec(head[0] ?? "");
  if (!m) throw new Error('the first line must be "METHOD /path HTTP/1.1"');
  const headers = parseHeaders(head.slice(1));
  const host = headers.find(([k]) => k.toLowerCase() === "host")?.[1] ?? original.url.host;
  const url = /^https?:\/\//i.test(m[2]!) ? new URL(m[2]!) : new URL(`${original.url.protocol}//${host}${m[2]!.startsWith("/") ? m[2] : `/${m[2]}`}`);
  const keepBinary = binaryPlaceholder !== undefined && body === binaryPlaceholder;
  return { method: m[1]!.toUpperCase(), url, headers, body: keepBinary ? original.body : Buffer.from(body, "utf8") };
}

export function editedResponse(original: ProxyResponse, raw: string, binaryPlaceholder: string | undefined): ProxyResponse {
  const { head, body } = splitRaw(raw);
  const m = /^HTTP\/[\d.]+\s+(\d{3})\s*(.*)$/.exec(head[0] ?? "");
  if (!m) throw new Error('the first line must be "HTTP/1.1 200 OK"');
  const headers = parseHeaders(head.slice(1));
  const keepBinary = binaryPlaceholder !== undefined && body === binaryPlaceholder;
  if (keepBinary) return { status: Number(m[1]), statusText: m[2] ?? "", headers, body: original.body };
  // The body was shown decompressed: it goes out as plain text.
  return { status: Number(m[1]), statusText: m[2] ?? "", headers: headers.filter(([k]) => k.toLowerCase() !== "content-encoding"), body: Buffer.from(body, "utf8") };
}

export class Interceptor {
  readonly events = new EventEmitter();
  private readonly pending = new Map<string, { msg: PendingMessage; resolve: (d: Decision) => void; timer: ReturnType<typeof setTimeout>; stall: ReturnType<typeof setTimeout>; validate: (raw: string) => void }>();

  settings(e: Engagement): InterceptSettings {
    return { ...DEFAULT_INTERCEPT, ...(e.getMeta<Partial<InterceptSettings>>("intercept") ?? {}) };
  }

  rules(e: Engagement): ReplaceRule[] {
    return e.getMeta<ReplaceRule[]>("proxyRules") ?? [];
  }

  list(engagementId?: string): PendingMessage[] {
    return [...this.pending.values()].map((p) => p.msg).filter((m) => !engagementId || m.engagementId === engagementId);
  }

  /** Throws (and keeps the message waiting) if the edited text is not a valid message. */
  decide(id: string, decision: Decision): boolean {
    const p = this.pending.get(id);
    if (!p) return false;
    if (decision.action === "forward" && decision.raw !== undefined) p.validate(decision.raw);
    clearTimeout(p.timer);
    clearTimeout(p.stall);
    this.pending.delete(id);
    p.resolve(decision);
    this.events.emit("changed", p.msg.engagementId);
    return true;
  }

  /** Everything waiting goes out unchanged (interception off, project switch, shutdown). */
  releaseAll(engagementId?: string): number {
    let n = 0;
    for (const p of this.list(engagementId)) if (this.decide(p.id, { action: "forward" })) n++;
    return n;
  }

  private matches(e: Engagement, s: InterceptSettings, req: ProxyRequest): boolean {
    if (s.skipStatic && STATIC.test(req.url.pathname)) return false;
    if (s.hostContains && !req.url.host.toLowerCase().includes(s.hostContains.toLowerCase())) return false;
    if (s.methods.length && !s.methods.includes(req.method)) return false;
    if (s.inScopeOnly && e.checkScope(req.url.href, "passive", { type: "human" }).decision === "deny") return false;
    return true;
  }

  private wait(msg: PendingMessage, validate: (raw: string) => void): Promise<Decision> {
    return new Promise((resolve) => {
      // Nobody answers: it goes out as it came, so the browser does not hang.
      const timer = setTimeout(() => this.decide(msg.id, { action: "forward" }), TIMEOUT_MS);
      const stall = setTimeout(() => this.events.emit("stalled", msg.engagementId, this.list(msg.engagementId).length), STALL_MS);
      this.pending.set(msg.id, { msg, resolve, timer, stall, validate });
      this.events.emit("changed", msg.engagementId);
    });
  }

  async onRequest(e: Engagement, req0: ProxyRequest): Promise<{ req: ProxyRequest; edited: boolean } | undefined> {
    const ruled = applyRequestRules(this.rules(e), req0);
    let req = ruled.req;
    let edited = ruled.edited;
    const s = this.settings(e);
    if (!s.requests || !this.matches(e, s, req)) return { req, edited };
    const shown = requestRaw(req);
    const placeholder = shown.binary ? splitRaw(shown.raw).body : undefined;
    const original = req;
    const d = await this.wait(
      { id: ulid(), kind: "request", engagementId: e.info.id, createdAt: new Date().toISOString(), method: req.method, url: req.url.href, raw: shown.raw, binaryBody: shown.binary },
      (raw) => void editedRequest(original, raw, placeholder),
    );
    if (d.action === "drop") return undefined;
    if (d.raw !== undefined && d.raw.replace(/\r\n/g, "\n") !== shown.raw) {
      req = editedRequest(req, d.raw, placeholder);
      edited = true;
    }
    return { req, edited };
  }

  /** A WebSocket message on its way: forwarded (maybe edited) or dropped. */
  async onWsMessage(
    e: Engagement,
    m: { url: string; direction: "out" | "in"; opcode: number; payload: Buffer },
  ): Promise<{ payload: Buffer; opcode: number; edited: boolean } | undefined> {
    const s = this.settings(e);
    const keep = { payload: m.payload, opcode: m.opcode, edited: false };
    if (!s.wsMessages) return keep;
    const url = new URL(m.url);
    if (s.hostContains && !url.host.toLowerCase().includes(s.hostContains.toLowerCase())) return keep;
    if (s.inScopeOnly && e.checkScope(url.href.replace(/^ws/, "http"), "passive", { type: "human" }).decision === "deny") return keep;
    const text = m.opcode === 1 || (m.opcode !== 2 && Buffer.from(m.payload.toString("utf8"), "utf8").equals(m.payload));
    const shown = text ? m.payload.toString("utf8") : `[binary message: ${m.payload.length} bytes; sent unchanged unless edited]`;
    const d = await this.wait(
      { id: ulid(), kind: m.direction === "out" ? "ws_out" : "ws_in", engagementId: e.info.id, createdAt: new Date().toISOString(), method: m.direction === "out" ? "WS →" : "WS ←", url: m.url, raw: shown, binaryBody: !text },
      () => undefined,
    );
    if (d.action === "drop") return undefined;
    if (d.raw === undefined || d.raw === shown) return keep;
    return { payload: Buffer.from(d.raw, "utf8"), opcode: 1, edited: true };
  }

  async onResponse(e: Engagement, req: ProxyRequest, res0: ProxyResponse): Promise<{ res: ProxyResponse; edited: boolean } | undefined> {
    const ruled = applyResponseRules(this.rules(e), res0);
    let res = ruled.res;
    let edited = ruled.edited;
    const s = this.settings(e);
    if (!s.responses || !this.matches(e, s, req)) return { res, edited };
    const shown = responseRaw(res);
    const placeholder = shown.binary ? splitRaw(shown.raw).body : undefined;
    const original = res;
    const d = await this.wait(
      { id: ulid(), kind: "response", engagementId: e.info.id, createdAt: new Date().toISOString(), method: req.method, url: req.url.href, status: res.status, raw: shown.raw, binaryBody: shown.binary },
      (raw) => void editedResponse(original, raw, placeholder),
    );
    if (d.action === "drop") return undefined;
    if (d.raw !== undefined && d.raw.replace(/\r\n/g, "\n") !== shown.raw) {
      res = editedResponse(res, d.raw, placeholder);
      edited = true;
    }
    return { res, edited };
  }
}

/**
 * The proxy's hooks for interception. The agents' browser is never held: only a person at the
 * screen can release a held message, and an agent would hang waiting. It passes through untouched
 * (an empty answer from a hook means "dropped").
 */
export function interceptionHooks(interceptor: Interceptor, agentSource: string): import("./server.js").ProxyHooks {
  return {
    request: (e, req, ctx) => (ctx.source === agentSource ? Promise.resolve({ req, edited: false }) : interceptor.onRequest(e, req)),
    response: (e, req, res, ctx) => (ctx.source === agentSource ? Promise.resolve({ res, edited: false }) : interceptor.onResponse(e, req, res)),
    ws: (e, m) => interceptor.onWsMessage(e, m),
  };
}
