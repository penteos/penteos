import { gapLine, gapsLimiting } from "../../tools/capabilities.js";
import type { RunOutcome } from "../../tools/runner.js";
import { defineOperation, OperationError } from "../registry.js";
import { RiskLevel } from "@penteos/schema";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { WSTG } from "../../wstg.js";
import { engagementId, outcome } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Web: requests, coverage

defineOperation({
  name: "http.send",
  title: "Send an HTTP request",
  description:
    'Sends a raw HTTP request exactly as written (like Burp Repeater) to an in-scope origin and returns the response. Redirects are not followed. The exchange is kept as raw (use its rawId for evidence) and the endpoint, method, status and parameters land in the graph. Prefer this over curl for web testing. Use {{secret:name}} for credentials and session cookies. raw example: "POST /login.php HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\nCookie: {{secret:app_session}}\n\nusername=admin&password={{secret:app_admin}}".',
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    origin: z.string().describe("Scheme, host and port: http://127.0.0.1:4280"),
    raw: z.string().min(1).describe("Request line, headers, blank line, body"),
    risk: RiskLevel.default("active"),
  }),
  handler: async (input, ctx) => {
    let result: RunOutcome;
    try {
      result = await ctx.runner(input.engagementId).runHttp({ origin: input.origin, raw: input.raw, risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});



defineOperation({
  name: "web.harvest_scripts",
  title: "Harvest a web app's JavaScript",
  description:
    "Fetches a page and the JavaScript it loads, and pulls out what the application leaks in its own code: the API endpoints it calls, the hosts of other environments (staging, internal APIs), its routes (admin panel, portal) and credentials left in the bundle. In-scope endpoints and apps are added to the graph to test next; out-of-scope hosts, secrets and source maps become observations. This is usually the first thing to do on a single-page app: its whole API surface ships in the bundle. Pass the page URL (or explicit script URLs). Only in-scope URLs are fetched.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    url: z.string().url().describe("The page to start from (its scripts are discovered), or a bundle URL directly"),
    scripts: z.array(z.string().url()).optional().describe("Explicit script URLs instead of discovering them from the page"),
    risk: RiskLevel.default("active"),
    maxScripts: z.number().int().min(1).max(60).optional(),
  }),
  handler: async (input, ctx) => {
    let result: RunOutcome;
    try {
      result = await ctx.runner(input.engagementId).harvestScripts({ url: input.url, ...(input.scripts ? { scripts: input.scripts } : {}), risk: input.risk, ...(input.maxScripts ? { maxScripts: input.maxScripts } : {}) }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});

defineOperation({
  name: "web.read_api_spec",
  title: "Read an API's contract",
  description:
    "Reads an API's published contract (OpenAPI 3 or Swagger 2 JSON: /api/docs-json, /openapi.json, /swagger.json, /v3/api-docs…) from an in-scope URL and adds every route to the graph with its methods, parameters and declared authentication. Then web_probe_endpoints sweeps them all. A contract served without credentials is recorded as an observation (template exposed-api-documentation).",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, url: z.string().url().describe("The contract URL (JSON)"), risk: RiskLevel.default("active") }),
  handler: async (input, ctx) => {
    let result: RunOutcome;
    try {
      result = await ctx.runner(input.engagementId).readApiSpec({ url: input.url, risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});

defineOperation({
  name: "web.probe_endpoints",
  title: "Probe endpoints for the auth boundary",
  description:
    "Requests a set of endpoints of one in-scope origin without credentials (and, with a header, with an invalid or other-tenant token) to map where authentication is enforced. The endpoints that answer with data where their siblings refuse are the authorization gaps: a route that forgot its check, or broken object/function-level authorization. Flags them as observations and records coverage. Pass paths, or leave empty to probe every endpoint the graph knows for that app (harvest or map it first). When a single-page app calls an API on another host with relative paths (web_harvest_scripts reports the API base it found), sweep them there in one call: origin = the API's origin, fromOrigin = the app's origin; Penteos measures the base path the calls live under (/api, /api/v1…) and requests them all. Use header to test an invalid token, e.g. 'Authorization: Bearer {{secret:other_tenant_token}}'.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    origin: z.string().url().describe("The in-scope origin to probe (e.g. https://backend3.example.com)"),
    paths: z.array(z.string().startsWith("/")).optional().describe("Endpoint paths; empty means every endpoint known for this app"),
    header: z.string().optional().describe("A header to also send (invalid or other-tenant token); use {{secret:name}}"),
    risk: RiskLevel.default("active"),
    maxRequests: z.number().int().min(1).max(3000).optional(),
    fromOrigin: z.string().url().optional().describe("Take the known endpoints of this other app (e.g. the single-page app whose JavaScript calls this API) instead of the probed origin's own"),
    basePath: z.string().startsWith("/").optional().describe("Prefix for those paths on the probed origin, e.g. '/api'. Leave it out with fromOrigin: Penteos measures under which base path the calls exist and uses it"),
  }),
  handler: async (input, ctx) => {
    let result: RunOutcome;
    try {
      result = await ctx.runner(input.engagementId).probeEndpoints({ origin: input.origin, ...(input.paths ? { paths: input.paths } : {}), ...(input.header ? { header: input.header } : {}), risk: input.risk, ...(input.maxRequests ? { maxRequests: input.maxRequests } : {}), ...(input.fromOrigin ? { fromOrigin: input.fromOrigin } : {}), ...(input.basePath ? { basePath: input.basePath } : {}) }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});

defineOperation({
  name: "web.probe_rate_limit",
  title: "Test rate limiting",
  description:
    "Sends the same request (a login, a password reset, an OTP or code check) a bounded number of times and looks for a defence: 429/423, a lockout or captcha message, a changing answer or a growing delay. Stops at the first sign of one. Sends at least 15 (limits commonly start between 10 and 20); if none appears, records an observation on the endpoint, and a 429 seen there later by any request settles it. Test every authentication endpoint of an origin in ONE call (raw plus more): one approval, one verdict per endpoint. The verdict is conclusive: never re-test it by other means. Use a test account or an invented user, never a real person's account: repeated attempts can lock it. Intrusive by default.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    origin: z.string().url(),
    raw: z.string().min(1).describe("The request to repeat, as in http_send (use {{secret:name}} for anything sensitive)"),
    more: z.array(z.string().min(1)).max(4).optional().describe("More requests on the same origin to test in the same call and approval (password reset, OTP or code checks)"),
    /** At least 15 are sent: limits commonly start between 10 and 20, and fewer would only say "none seen yet". */
    attempts: z.number().int().min(3).max(40).default(20),
    risk: RiskLevel.default("intrusive"),
  }),
  handler: async (input, ctx) => {
    let result: RunOutcome;
    try {
      result = await ctx.runner(input.engagementId).probeRateLimit({ origin: input.origin, raw: input.raw, ...(input.more?.length ? { more: input.more } : {}), attempts: input.attempts, risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});

defineOperation({
  name: "webapp.coverage",
  title: "OWASP coverage of an application",
  description: "Which OWASP WSTG categories were tested on a web application and with what result.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, webappId: z.string() }),
  handler: (input, ctx) => {
    const app = ctx.engagement(input.engagementId).get(input.webappId);
    if (!app || app.kind !== "webapp") throw new OperationError("NOT_FOUND", `webapp ${input.webappId} not found`);
    const cov = (app.attributes.coverage ?? {}) as Record<string, unknown>;
    return WSTG.map((c) => ({ ...c, ...((cov[c.id] as object) ?? { status: "untested" }) }));
  },
});

defineOperation({
  name: "webapp.set_coverage",
  title: "Record OWASP coverage",
  description:
    "Records the state of an OWASP WSTG category on a web application: in_progress, tested (nothing found), partial (tested, but not all of it could be done), vulnerable (link the finding in the note) or n/a. Update it as you test, so the operator and the report show what was covered. If a tool gap affects that category on that app, 'tested' is recorded as 'partial' with the reason: the coverage never claims what a missing tool kept from being done.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    webappId: z.string(),
    category: z.enum(WSTG.map((c) => c.id) as [string, ...string[]]),
    status: z.enum(["untested", "in_progress", "tested", "partial", "vulnerable", "n/a"]),
    note: z.string().optional(),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const app = e.get(input.webappId);
    if (!app || app.kind !== "webapp") throw new OperationError("NOT_FOUND", `webapp ${input.webappId} not found`);
    // "Tested" while a tool gap affects this category on this app is "partial", with the reason.
    const lang = e.info.language ?? "en";
    const limiting = input.status === "tested" ? gapsLimiting(e, String(app.attributes.origin), input.category) : [];
    const status = limiting.length ? "partial" : input.status;
    const why = limiting.map((g) => gapLine(g, lang)).join(" · ");
    const note = [input.note, why && (lang === "en" ? `Partial: ${why}` : `Parcial: ${why}`)].filter(Boolean).join("\n");
    const coverage = {
      ...((app.attributes.coverage ?? {}) as Record<string, unknown>),
      [input.category]: { status, ...(note ? { note } : {}), by: ctx.caller.name ?? ctx.caller.actor.type, at: new Date().toISOString() },
    };
    return e.editEntity(app.id, { coverage }, ctx.caller.actor);
  },
});

defineOperation({
  name: "coverage.matrix",
  title: "Coverage of every application",
  description: "OWASP WSTG coverage of every web application in scope at once: for each one, each category's state and note, and how many findings it has. What is still untested is what is left to do.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const findings = e.query({ kind: "finding", limit: 5000 });
    const apps = e.query({ kind: "webapp", limit: 500 }).filter((a) => !a.outOfScope);
    const endpoints = e.query({ kind: "endpoint", limit: 50_000 });
    return {
      categories: WSTG,
      apps: apps.map((app) => {
        const cov = (app.attributes.coverage ?? {}) as Record<string, object>;
        // A finding belongs to the app when it affects the app itself or one of its endpoints.
        const ids = new Set([app.id, ...endpoints.filter((ep) => ep.attributes.webappId === app.id).map((ep) => ep.id)]);
        const linked = findings.filter((f) => ((f.attributes.instances as Array<{ entity?: { id?: string } }>) ?? []).some((i) => i.entity?.id && ids.has(i.entity.id))).length;
        return { id: app.id, origin: String(app.attributes.origin), findings: linked, coverage: WSTG.map((c) => ({ id: c.id, ...((cov[c.id] as object) ?? { status: "untested" }) })) };
      }),
    };
  },
});
