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
    "Fetches a page and ALL of its JavaScript - not only the scripts in the HTML: every chunk, dynamic import and Next.js build manifest the code names is followed (in scope, politely) - and each source map the site serves, recovering the original files. Everything is kept in the project (work/js/<host>/: bundles/, sources/, index.json) so you can search it with run_exec (grep, no targets). It pulls out the API endpoints, hosts of other environments, routes, credentials and shipped configuration (error tracker DSNs, buckets, backends), internal addresses, message listeners without an origin check, DOM sinks, redirect parameters, fields the browser computes and sends, and Next.js server actions. Leads it opens (redirects, client-computed fields, server actions, message listeners) must be looked at before the round closes. Run it on every web application in scope, and on its login and admin pages: each screen loads its own chunks.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    url: z.string().url().describe("The page to start from (its scripts are discovered), or a bundle URL directly"),
    scripts: z.array(z.string().url()).optional().describe("Explicit script URLs instead of discovering them from the page"),
    risk: RiskLevel.default("active"),
    maxScripts: z.number().int().min(1).max(400).optional().describe("How many script files to read at most (default 200)"),
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
  name: "web.cross_account",
  title: "Replay one account's requests as another (IDOR/BOLA)",
  description: "With two test accounts: account A's requests (by default its GETs on resources with identifiers, taken from the proxy history - browse as A through Penteos first) are replayed with account B's session and with no session. B, or nobody, getting what only A should is IDOR/BOLA (or a missing check); with B a lower role on admin resources, privilege escalation. Sessions as header lines with saved secrets: 'Cookie: {{secret:account_a}}'. Pass raws to test other requests (a POST may change data: only when you mean it).",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, origin: z.string().url(), accountA: z.string().min(3), accountB: z.string().min(3), raws: z.array(z.string().min(1)).max(60).optional(), risk: RiskLevel.default("active") }),
  handler: async (input, ctx) => outcome(await ctx.runner(input.engagementId).accountProbe({ check: "cross", origin: input.origin, accountA: input.accountA, accountB: input.accountB, ...(input.raws?.length ? { raws: input.raws } : {}), risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" }), ctx),
});

defineOperation({
  name: "web.probe_race",
  title: "Send a request several times at once (race condition)",
  description: "Sends the same request 2-10 times at once (each on its own connection) and says how many the server accepted. For actions that must happen once: a transfer against one balance, redeeming a code or coupon, a vote, a one-time code. Intrusive (it may move money in the test account): it asks; use a test account with a small amount and check the state after.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, origin: z.string().url(), raw: z.string().min(1), count: z.number().int().min(2).max(10).default(5), risk: RiskLevel.default("intrusive") }),
  handler: async (input, ctx) => outcome(await ctx.runner(input.engagementId).accountProbe({ check: "race", origin: input.origin, raw: input.raw, count: input.count, risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" }), ctx),
});

defineOperation({
  name: "web.probe_logout",
  title: "Check a session ends on logout",
  description: "Sends an authenticated request (check, with a test account's session), then the logout request, then the first one again with the same session: still answered as before means logging out does not end the session on the server. It logs the test account out.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, origin: z.string().url(), check: z.string().min(1).describe("An authenticated raw request, e.g. GET /api/user with Cookie: {{secret:account_a}}"), logout: z.string().min(1).describe("The raw logout request, with the same session"), risk: RiskLevel.default("active") }),
  handler: async (input, ctx) => outcome(await ctx.runner(input.engagementId).accountProbe({ check: "logout", origin: input.origin, check_raw: input.check, logout_raw: input.logout, risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" }), ctx),
});

defineOperation({
  name: "web.probe_redirects",
  title: "Probe for open redirects",
  description: "Sends the parameters that say where to go next (the ones the JavaScript names, the usual ones, or the ones given: targets [{path, param}]) an outside address in the encodings filters miss, and reports each that sends the browser there (Location, meta refresh, script). Login, logout, SSO and callback routes first.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, origin: z.string().url(), targets: z.array(z.object({ path: z.string().startsWith("/"), param: z.string().min(1) })).max(80).optional(), risk: RiskLevel.default("active") }),
  handler: async (input, ctx) => outcome(await ctx.runner(input.engagementId).webProbe({ check: "redirect", origin: input.origin, ...(input.targets?.length ? { targets: input.targets } : {}), risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" }), ctx),
});

defineOperation({
  name: "web.probe_traversal",
  title: "Probe path parameters for traversal",
  description: "For endpoints with a path parameter (/api/onboarding/{id}, from the graph or given as templates), compares a normal value with ../ in its encodings (%2f, %252f, ..;/, %2e%2e…) and reports where the parameter walks out of its route (success where a normal value fails, another kind of answer). Run it on every templated API route, and on any route that answered 5xx to an odd value.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, origin: z.string().url(), templates: z.array(z.string().startsWith("/")).max(50).optional(), risk: RiskLevel.default("active") }),
  handler: async (input, ctx) => outcome(await ctx.runner(input.engagementId).webProbe({ check: "traversal", origin: input.origin, ...(input.templates?.length ? { templates: input.templates } : {}), risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" }), ctx),
});

defineOperation({
  name: "web.probe_session_guard",
  title: "Probe panels with an invented session",
  description: "Asks for each screen that should need a session (dashboard, admin, account… from the JavaScript's routes, or the paths given) without a cookie and with invented session cookies, and reports the ones that send to the login without a cookie but serve themselves with a made-up one: the guard checks the cookie exists, not that the session is valid. Run it on every app with a login, admin panels first.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, origin: z.string().url(), paths: z.array(z.string().startsWith("/")).max(20).optional(), risk: RiskLevel.default("active") }),
  handler: async (input, ctx) => outcome(await ctx.runner(input.engagementId).webProbe({ check: "guard", origin: input.origin, ...(input.paths?.length ? { paths: input.paths } : {}), risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" }), ctx),
});

defineOperation({
  name: "dns.check_mail",
  title: "Check a domain's mail spoofing defences",
  description: "SPF, DMARC and DKIM (common selectors) of a domain, with lookups only (passive): missing or permissive SPF, DMARC missing or p=none, no reports. Run it on the client's main domains: a spoofable domain is a phishing vector against their own customers.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, domain: z.string().min(3) }),
  handler: async (input, ctx) => outcome(await ctx.runner(input.engagementId).checkDns({ kind: "mail", domain: input.domain }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" }), ctx),
});

defineOperation({
  name: "dns.check_takeover",
  title: "Check names for subdomain takeover",
  description: "Follows each name's CNAME chain (passive lookups) and reports the ones ending at a service that can be claimed (GitHub Pages, S3, CloudFront, Heroku, Azure, Netlify, Vercel, Shopify, Fastly and others) while unclaimed, or at a name that does not exist. Names in scope for active work are also asked over HTTP(S) for the service's 'does not exist' page. Without names, every domain in the graph that is in scope. Run it after subdomain discovery, and on any name a CDN cannot reach (530).",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, names: z.array(z.string().min(3)).max(300).optional() }),
  handler: async (input, ctx) => outcome(await ctx.runner(input.engagementId).checkDns({ kind: "takeover", ...(input.names?.length ? { names: input.names } : {}) }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" }), ctx),
});

defineOperation({
  name: "web.check_transport",
  title: "Check TLS, HTTPS and security headers",
  description:
    "Checks how a site protects the connection, in one call: TLS versions still accepted (SSLv3, TLS 1.0/1.1) and weak ciphers (3DES, RC4, NULL/EXPORT) with hand-built handshakes, the certificate (expired, wrong name, untrusted), whether plain HTTP redirects to HTTPS, HSTS, cookie flags (Secure, HttpOnly, SameSite), CSP (unsafe-inline/eval, wildcards), framing (clickjacking) and CORS (an arbitrary or null origin reflected, with credentials). Run it on every web host in scope - payments and login sites first. Each problem becomes an observation with the evidence.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, target: z.string().min(1).describe("The site: https://host[:port] or the host"), path: z.string().optional().describe("The page to read headers from (default /)"), risk: RiskLevel.default("active") }),
  handler: async (input, ctx) => {
    let result: RunOutcome;
    try {
      result = await ctx.runner(input.engagementId).checkTransport({ target: input.target, ...(input.path ? { path: input.path } : {}), risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});

defineOperation({
  name: "web.probe_server_actions",
  title: "Probe Next.js server actions",
  description:
    "Calls each Next.js server action the bundles revealed (web_harvest_scripts) once, with no arguments: without a session by default, or with a lower role's session (header, e.g. 'Cookie: {{secret:user_session}}'). Says which ran, which refused, which failed on the input (leads) and which no longer exist. Post them to the page they belong to (page: '/es/login', '/dashboard'). Calling an action can change data: it is intrusive and asks for approval; prefer a test environment or test accounts.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    origin: z.string().url(),
    page: z.string().optional().describe("The page path the actions are posted to (default /)"),
    header: z.string().optional().describe("A session to call them with, as a header line: 'Cookie: {{secret:name}}'"),
    ids: z.array(z.string().regex(/^[0-9a-f]{40,42}$/)).max(300).optional(),
    risk: RiskLevel.default("intrusive"),
  }),
  handler: async (input, ctx) => {
    let result: RunOutcome;
    try {
      result = await ctx.runner(input.engagementId).probeServerActions({ origin: input.origin, ...(input.page ? { page: input.page } : {}), ...(input.header ? { header: input.header } : {}), ...(input.ids?.length ? { ids: input.ids } : {}), risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});

defineOperation({
  name: "webapp.set_coverage",
  title: "Record OWASP coverage",
  description:
    "Records the state of an OWASP WSTG category (or several at once with categories) on a web application: in_progress, tested (nothing found), partial (tested, but not all of it could be done: say why in the note, e.g. 'no test account'), vulnerable (link the finding in the note) or n/a (with the reason). Update it as you test, so the operator and the report show what was covered. If a tool gap affects that category on that app, 'tested' is recorded as 'partial' with the reason: the coverage never claims what a missing tool kept from being done.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    webappId: z.string(),
    category: z.enum(WSTG.map((c) => c.id) as [string, ...string[]]).optional(),
    categories: z.array(z.enum(WSTG.map((c) => c.id) as [string, ...string[]])).max(20).optional(),
    status: z.enum(["untested", "in_progress", "tested", "partial", "vulnerable", "n/a"]),
    note: z.string().optional(),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const app = e.get(input.webappId);
    if (!app || app.kind !== "webapp") throw new OperationError("NOT_FOUND", `webapp ${input.webappId} not found`);
    const categories = [...new Set([...(input.category ? [input.category] : []), ...(input.categories ?? [])])];
    if (!categories.length) throw new OperationError("VALIDATION_ERROR", "pass category or categories");
    // Not tested, partly or not at all, is said with why: the report and the client read it.
    if (ctx.caller.actor.type === "agent" && (input.status === "partial" || input.status === "n/a") && !input.note?.trim()) throw new OperationError("VALIDATION_ERROR", `${input.status} needs a note saying why (e.g. "no test account", "no login on this app")`);
    const lang = e.info.language ?? "en";
    const coverage: Record<string, unknown> = { ...((app.attributes.coverage ?? {}) as Record<string, unknown>) };
    for (const category of categories) {
      // "Tested" while a tool gap affects this category on this app is "partial", with the reason.
      const limiting = input.status === "tested" ? gapsLimiting(e, String(app.attributes.origin), category) : [];
      const status = limiting.length ? "partial" : input.status;
      const why = limiting.map((g) => gapLine(g, lang)).join(" · ");
      const note = [input.note, why && (lang === "en" ? `Partial: ${why}` : `Parcial: ${why}`)].filter(Boolean).join("\n");
      coverage[category] = { status, ...(note ? { note } : {}), by: ctx.caller.name ?? ctx.caller.actor.type, at: new Date().toISOString() };
    }
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
