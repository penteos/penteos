import type { PluginProxyHook } from "@penteos/schema";
import type { Engagement } from "../engagement.js";
import type { ProxyHooks, ProxyRequest, ProxyResponse } from "../proxy/server.js";
import { PROXY_LIMITS, type PluginRuntime } from "./runtime.js";

/**
 * Plugins in the proxy's path: what a hook sees, what it may
 * change, and how the proxy's own hooks (the operator's interception) come after them.
 */

const TEXT = /^(text\/|application\/(json|xml|javascript|x-www-form-urlencoded|graphql|[a-z.+-]*\+(json|xml)))/i;

function headerOf(headers: Array<[string, string]>, name: string): string | undefined {
  return headers.find(([k]) => k.toLowerCase() === name)?.[1];
}

function bodyOut(body: Buffer, headers: Array<[string, string]>): Record<string, unknown> {
  if (body.length > PROXY_LIMITS.bodyBytes) return { body: null, bodyOmitted: body.length };
  const text = TEXT.test(headerOf(headers, "content-type") ?? "");
  return text ? { body: body.toString("utf8"), bodyEncoding: "text" } : { body: body.toString("base64"), bodyEncoding: "base64" };
}

function globMatch(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  return p.startsWith("*.") ? h.endsWith(p.slice(1)) && h.length > p.length - 1 : h === p;
}

export function hookMatches(hook: PluginProxyHook, req: ProxyRequest, res?: ProxyResponse): boolean {
  if (hook.hosts?.length && !hook.hosts.some((p) => globMatch(p, req.url.hostname))) return false;
  if (hook.methods?.length && !hook.methods.includes(req.method.toUpperCase())) return false;
  if (hook.path !== undefined) {
    try {
      if (!new RegExp(hook.path).test(req.url.pathname + req.url.search)) return false;
    } catch {
      return false;
    }
  }
  if (res && hook.contentTypes?.length) {
    const ct = (headerOf(res.headers, "content-type") ?? "").toLowerCase();
    if (!hook.contentTypes.some((c) => ct.startsWith(c.toLowerCase()))) return false;
  }
  return true;
}

function requestView(req: ProxyRequest): Record<string, unknown> {
  return { method: req.method, url: req.url.href, headers: req.headers, ...bodyOut(req.body, req.headers) };
}

function responseView(req: ProxyRequest, res: ProxyResponse): Record<string, unknown> {
  return { request: { method: req.method, url: req.url.href, headers: req.headers }, status: res.status, statusText: res.statusText, headers: res.headers, ...bodyOut(res.body, res.headers) };
}

/** Headers as a plugin may give them back: [[k, v], …] or { k: v }. */
function headersIn(v: unknown): Array<[string, string]> | undefined {
  if (Array.isArray(v)) return v.filter((p): p is [unknown, unknown] => Array.isArray(p) && p.length === 2).map(([k, x]) => [String(k), String(x)]);
  if (v && typeof v === "object") return Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, String(x)]);
  return undefined;
}

function bodyIn(out: Record<string, unknown>, given: Record<string, unknown>): Buffer | undefined {
  if (typeof out.body !== "string") return undefined;
  const encoding = out.bodyEncoding === "base64" || (out.bodyEncoding === undefined && given.bodyEncoding === "base64") ? "base64" : "utf8";
  return Buffer.from(out.body, encoding);
}

/** A request with a plugin's changes; unchanged when it gave none (or something that is not one). */
export function applyRequestChange(req: ProxyRequest, given: Record<string, unknown>, out: unknown): { req: ProxyRequest; edited: boolean } {
  if (!out || typeof out !== "object" || Array.isArray(out)) return { req, edited: false };
  const o = out as Record<string, unknown>;
  let next = req;
  if (typeof o.method === "string" && /^[A-Z]{3,10}$/.test(o.method)) next = { ...next, method: o.method };
  if (typeof o.url === "string") {
    try {
      const url = new URL(o.url);
      if (url.protocol === "http:" || url.protocol === "https:") next = { ...next, url };
    } catch {
      /* not a URL: the original stays */
    }
  }
  const headers = headersIn(o.headers);
  if (headers) next = { ...next, headers };
  const body = given.bodyOmitted === undefined ? bodyIn(o, given) : undefined;
  if (body) next = { ...next, body };
  return { req: next, edited: next !== req };
}

export function applyResponseChange(res: ProxyResponse, given: Record<string, unknown>, out: unknown): { res: ProxyResponse; edited: boolean } {
  if (!out || typeof out !== "object" || Array.isArray(out)) return { res, edited: false };
  const o = out as Record<string, unknown>;
  let next = res;
  if (typeof o.status === "number" && Number.isInteger(o.status) && o.status >= 100 && o.status <= 599) next = { ...next, status: o.status, ...(typeof o.statusText === "string" ? { statusText: o.statusText } : {}) };
  const headers = headersIn(o.headers);
  if (headers) next = { ...next, headers };
  const body = given.bodyOmitted === undefined ? bodyIn(o, given) : undefined;
  if (body) next = { ...next, body };
  return { res: next, edited: next !== res };
}

/** The proxy hooks of the plugins enabled in each project. */
export function pluginProxyHooks(runtime: PluginRuntime): ProxyHooks {
  return {
    request: async (engagement: Engagement, req: ProxyRequest) => {
      let current = req;
      let edited = false;
      for (const { pluginId, hook } of runtime.proxyHooksFor(engagement, "request")) {
        if (!hookMatches(hook, current)) continue;
        const given = requestView(current);
        const out = await runtime.proxyCall(pluginId, hook, engagement, given);
        if (!hook.modify) continue;
        const r = applyRequestChange(current, given, out);
        current = r.req;
        edited ||= r.edited;
      }
      return { req: current, edited };
    },
    response: async (engagement: Engagement, req: ProxyRequest, res: ProxyResponse) => {
      let current = res;
      let edited = false;
      for (const { pluginId, hook } of runtime.proxyHooksFor(engagement, "response")) {
        if (!hookMatches(hook, req, current)) continue;
        const given = responseView(req, current);
        const out = await runtime.proxyCall(pluginId, hook, engagement, given);
        if (!hook.modify) continue;
        const r = applyResponseChange(current, given, out);
        current = r.res;
        edited ||= r.edited;
      }
      return { res: current, edited };
    },
  };
}

/** Two sets of proxy hooks one after the other: what the first lets through reaches the second. */
export function composeProxyHooks(first: ProxyHooks, second: ProxyHooks): ProxyHooks {
  return {
    request: async (e, req, ctx) => {
      const a = first.request ? await first.request(e, req, ctx) : { req, edited: false };
      if (!a) return undefined;
      if (!second.request) return a;
      const b = await second.request(e, a.req, ctx);
      return b ? { req: b.req, edited: a.edited || b.edited } : undefined;
    },
    response: async (e, req, res, ctx) => {
      const a = first.response ? await first.response(e, req, res, ctx) : { res, edited: false };
      if (!a) return undefined;
      if (!second.response) return a;
      const b = await second.response(e, req, a.res, ctx);
      return b ? { res: b.res, edited: a.edited || b.edited } : undefined;
    },
    ...(first.ws || second.ws ? { ws: second.ws ?? first.ws } : {}),
  };
}
