import { defineOperation, OperationError, type OperationContext } from "../registry.js";
import { z } from "zod";
import { DEFAULT_PROXY_SETTINGS, type ProxySettings } from "../../proxy/server.js";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId, untrusted } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Intercepting proxy

const proxySettingsOf = (e: ReturnType<OperationContext["engagement"]>): ProxySettings => ({ ...DEFAULT_PROXY_SETTINGS, ...(e.getMeta<Partial<ProxySettings>>("proxy") ?? {}) });

export function requireProxy(ctx: OperationContext) {
  if (!ctx.proxy) throw new OperationError("VALIDATION_ERROR", "this core has no proxy running (it runs with the desktop app, on this machine)");
  return ctx.proxy;
}

defineOperation({
  name: "proxy.status",
  title: "Proxy status",
  description: "Where the intercepting proxy listens, its credentials for this project and its settings.",
  kind: "read",
  actors: ["human"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const p = requireProxy(ctx).status();
    return { ...p, engagementId: e.info.id, username: e.info.id, settings: proxySettingsOf(e) };
  },
});

defineOperation({
  name: "proxy.ca",
  title: "Proxy certificate",
  description: "Penteos's CA certificate, to import in Burp, Caido or a browser that should go through the proxy.",
  kind: "read",
  actors: ["human"],
  input: z.object({}),
  handler: (_input, ctx) => requireProxy(ctx).ca(),
});

defineOperation({
  name: "proxy.let_through",
  title: "Let a host through",
  description:
    "Lets one out-of-scope host through the operator's own browser for a while (15 minutes by default), without adding a scope rule. Traffic is still recorded, marked out of scope. Only a person can do this; the agents propose scope rules instead.",
  kind: "target",
  actors: ["human"],
  input: z.object({ engagementId, host: z.string().min(1).max(253).regex(/^[A-Za-z0-9.:\-\[\]]+$/, "a bare host name or IP"), minutes: z.number().int().min(1).max(240).optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const r = requireProxy(ctx).letThrough(e.info.id, input.host, input.minutes);
    e.audit(ctx.caller.actor, "proxy.let_through", { host: r.host }, { until: r.until });
    return r;
  },
});

defineOperation({
  name: "proxy.configure",
  title: "Configure the proxy",
  description: "Out-of-scope traffic (block or pass through unrecorded), whether to keep static files, and an upstream proxy to chain to (Burp, Caido).",
  kind: "target",
  actors: ["human"],
  input: z.object({
    engagementId,
    outOfScope: z.enum(["block", "passthrough"]).optional(),
    recordStatic: z.boolean().optional(),
    upstream: z
      .string()
      .regex(/^(https?:\/\/[^\s]+)?$/, "upstream must be http://host:port (or empty to remove it)")
      .optional(),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const next: ProxySettings = {
      ...proxySettingsOf(e),
      ...(input.outOfScope ? { outOfScope: input.outOfScope } : {}),
      ...(input.recordStatic !== undefined ? { recordStatic: input.recordStatic } : {}),
    };
    e.setMeta("proxy", next, ctx.caller.actor);
    if (input.upstream !== undefined) requireProxy(ctx).setUpstream(input.upstream || undefined);
    return { settings: next, upstream: ctx.proxy?.status().upstream ?? null };
  },
});

const ProxyFilter = {
  text: z.string().optional(),
  host: z.string().optional(),
  methods: z.array(z.string()).optional(),
  status: z.enum(["2xx", "3xx", "4xx", "5xx", "error"]).optional(),
  inScopeOnly: z.boolean().default(false),
  includeBlocked: z.boolean().default(false),
  includeStatic: z.boolean().default(false),
};

defineOperation({
  name: "proxy.history",
  title: "Proxy history",
  description:
    "Traffic that went through the proxy (what the operator browsed, newest first): method, URL, status, size, scope. Use it to see the flows the operator already walked through (logins, forms) before testing them.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, limit: z.number().int().min(1).max(5000).default(200), afterSeq: z.number().int().optional(), beforeSeq: z.number().int().optional(), ...ProxyFilter }),
  handler: (input, ctx) => {
    const { engagementId: id, ...q } = input;
    return ctx.engagement(id).queryProxy(q);
  },
});

defineOperation({
  name: "proxy.entry",
  title: "Proxy exchange",
  description: "One exchange of the proxy history: the full request and response as raw HTTP.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const entry = e.getProxyEntry(input.id);
    if (!entry) throw new OperationError("NOT_FOUND", `proxy entry ${input.id} not found`);
    let request = "";
    let response = "";
    if (entry.rawId) {
      const raw = e.readRaw(entry.rawId);
      const cut = entry.requestLength ?? raw.length;
      request = raw.subarray(0, cut).toString("utf8");
      response = raw.subarray(Math.min(cut + 4, raw.length)).toString("utf8");
    }
    return { entry, request: untrusted(ctx, request), response: untrusted(ctx, response) };
  },
});

defineOperation({
  name: "proxy.annotate",
  title: "Annotate a proxy exchange",
  description: "Adds a note or a highlight color to an exchange of the proxy history.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string(), note: z.string().max(2000).optional(), highlight: z.enum(["red", "orange", "yellow", "green", "blue", "violet", "none"]).optional() }),
  handler: (input, ctx) => {
    const r = ctx.engagement(input.engagementId).annotateProxyEntry(input.id, {
      ...(input.note !== undefined ? { note: input.note } : {}),
      ...(input.highlight ? { highlight: input.highlight === "none" ? null : input.highlight } : {}),
    });
    if (!r) throw new OperationError("NOT_FOUND", `proxy entry ${input.id} not found`);
    return r;
  },
});

defineOperation({
  name: "proxy.hosts",
  title: "Hosts seen by the proxy",
  description: "Hosts in the proxy history with how many exchanges each, and whether they are in scope.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => ctx.engagement(input.engagementId).proxyHosts(),
});
