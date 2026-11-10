import { isIP } from "node:net";
import { ulid } from "@penteos/schema";

/**
 * Looking at a real service before building a plugin for it (the Maestro's first step): one request,
 * its real status, headers and body. Third-party services only - never a project target (those go
 * through the usual tools, with scope and approvals) nor this machine's network. What it sees is kept
 * a while, so a test can replay exactly what the real service answered instead of an invented reply.
 */

export const PROBE_LIMITS = { bodyBytes: 256 * 1024, shownBytes: 12 * 1024, timeoutMs: 15_000, perMinute: 30, kept: 100 } as const;

export interface ProbeRequest {
  method?: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE";
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface ProbeResult {
  probeId: string;
  method: string;
  url: string;
  status: number;
  ms: number;
  headers: Record<string, string>;
  /** Where a redirect points (redirects are shown, not followed: the plugin will have to follow them). */
  location?: string;
  contentType?: string;
  bytes: number;
  /** Parsed when JSON; text otherwise (cut for reading; the whole of it is kept for a replay). */
  body: unknown;
  truncated: boolean;
  /** What the Maestro should notice (a key asked for, a redirect to another host, a rate limit…). */
  hints: string[];
}

export interface KeptProbe {
  method: string;
  url: string;
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

function privateHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (isIP(h) === 4) {
    const [a, b] = h.split(".").map(Number) as [number, number];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  if (isIP(h) === 6) return h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80");
  return false;
}

/** Why a probe may not go to this URL, or undefined when it may. */
export function probeRefusal(url: URL, inScope: (host: string) => boolean): string | undefined {
  if (url.protocol !== "https:" && url.protocol !== "http:") return "only http(s) services";
  if (privateHost(url.hostname)) return `${url.hostname} is on a private network: probes are for public third-party services`;
  if (inScope(url.hostname)) return `${url.hostname} is a target of this project: look at it with the usual tools (scope, risk and approvals apply), not with a probe`;
  return undefined;
}

export class Prober {
  private readonly kept = new Map<string, KeptProbe>();
  private times: number[] = [];

  constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  get(id: string): KeptProbe | undefined {
    return this.kept.get(id);
  }

  async probe(req: ProbeRequest, options: { inScope: (host: string) => boolean; redact?: (text: string) => string }): Promise<ProbeResult> {
    let url: URL;
    try {
      url = new URL(req.url);
    } catch {
      throw new Error(`not a URL: ${req.url}`);
    }
    const refusal = probeRefusal(url, options.inScope);
    if (refusal) throw new Error(refusal);
    const now = Date.now();
    this.times = this.times.filter((t) => now - t < 60_000);
    if (this.times.length >= PROBE_LIMITS.perMinute) throw new Error(`more than ${PROBE_LIMITS.perMinute} probes in a minute: look at what you have first`);
    this.times.push(now);
    const method = req.method ?? "GET";
    const headers: Record<string, string> = { "user-agent": "Penteos plugin builder", accept: "application/json, text/plain, */*", ...(req.headers ?? {}) };
    let body: string | undefined;
    if (req.body !== undefined && method !== "GET" && method !== "HEAD") {
      body = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
      if (typeof req.body !== "string" && !Object.keys(headers).some((k) => k.toLowerCase() === "content-type")) headers["content-type"] = "application/json";
    }
    const started = Date.now();
    const res = await this.fetchImpl(url, { method, headers, ...(body !== undefined ? { body } : {}), redirect: "manual", signal: AbortSignal.timeout(PROBE_LIMITS.timeoutMs) });
    const buf = Buffer.from(await res.arrayBuffer()).subarray(0, PROBE_LIMITS.bodyBytes);
    const ms = Date.now() - started;
    const redact = options.redact ?? ((t: string) => t);
    const out: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      out[k] = redact(v).slice(0, 500);
    });
    const contentType = out["content-type"];
    const text = redact(buf.toString("utf8"));
    let parsed: unknown = text;
    if (/json/i.test(contentType ?? "") || /^\s*[[{]/.test(text)) {
      try {
        parsed = JSON.parse(text);
      } catch {
        /* not JSON after all */
      }
    }
    const id = ulid();
    this.kept.set(id, { method, url: url.href, status: res.status, headers: out, body: parsed });
    while (this.kept.size > PROBE_LIMITS.kept) this.kept.delete(this.kept.keys().next().value!);
    const shown = typeof parsed === "string" ? parsed.slice(0, PROBE_LIMITS.shownBytes) : shrink(parsed);
    const location = out.location ? new URL(out.location, url).href : undefined;
    return {
      probeId: id,
      method,
      url: url.href,
      status: res.status,
      ms,
      headers: out,
      ...(location ? { location } : {}),
      ...(contentType ? { contentType } : {}),
      bytes: buf.length,
      body: shown,
      truncated: typeof parsed === "string" ? parsed.length > PROBE_LIMITS.shownBytes : JSON.stringify(parsed).length > PROBE_LIMITS.shownBytes,
      hints: hintsFor(res.status, url, location, text, out),
    };
  }
}

/** A JSON value cut down for reading: long arrays and strings shortened, the shape kept. */
function shrink(v: unknown, depth = 0): unknown {
  if (typeof v === "string") return v.length > 600 ? `${v.slice(0, 600)}…` : v;
  if (Array.isArray(v)) return depth > 6 ? `[${v.length} items]` : [...v.slice(0, 8).map((x) => shrink(x, depth + 1)), ...(v.length > 8 ? [`… ${v.length - 8} more`] : [])];
  if (v && typeof v === "object") {
    if (depth > 6) return "{…}";
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).slice(0, 60).map(([k, x]) => [k, shrink(x, depth + 1)]));
  }
  return v;
}

function hintsFor(status: number, url: URL, location: string | undefined, text: string, headers: Record<string, string>): string[] {
  const hints: string[] = [];
  if (location) {
    const to = new URL(location);
    hints.push(to.host === url.host ? `redirects to ${location}: the plugin must call that URL, or follow the redirect` : `redirects to another host (${to.host}): the plugin needs a net: permission for it (or net:* if it varies), or must call it directly`);
  }
  if (status === 401 || status === 403 || /\b(api[_ -]?key|valid key|unauthori[sz]ed|token required|forbidden|authentication)\b/i.test(text.slice(0, 2000))) {
    hints.push("it looks like the service needs a key or account: find out which (its docs), declare a secret setting, and ask the operator for it with plugin_draft_request_setting - or pick a service that needs none");
  }
  if (status === 429 || headers["retry-after"] || /rate.?limit|too many requests|quota/i.test(text.slice(0, 2000))) hints.push("rate limited: say so in the plugin's description, and handle the 429 with a clear message");
  if (status >= 500) hints.push("the service failed: try again later or with another input before concluding anything");
  if (status === 200 && /^\s*(error|invalid|no match|not found)\b/i.test(text)) hints.push("status 200 but the body reads like an error: the plugin must check the body, not only the status");
  return hints;
}
