import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";
import { fillTemplate, guardedRoutes, redirectsToCanary, traversalReached } from "../src/webprobes.js";

/**
 * Open redirect, path traversal in a path parameter and a guard that only checks a cookie exists:
 * what a real assessment found and Penteos did not look for (M5, A4, F4-1).
 */
describe("reading the answers", () => {
  it("sees a redirect to the canary in a Location, a meta refresh or a script", () => {
    expect(redirectsToCanary(302, [["Location", "https://penteos-redirect.invalid/"]], "", "https://a.test/login")).toBe(true);
    expect(redirectsToCanary(302, [["Location", "/\\penteos-redirect.invalid/"]], "", "https://a.test/login")).toBe(true);
    expect(redirectsToCanary(200, [], `<meta http-equiv="refresh" content="0;url=//penteos-redirect.invalid/">`, "https://a.test/")).toBe(true);
    expect(redirectsToCanary(302, [["Location", "/dashboard"]], "", "https://a.test/login")).toBe(false);
  });

  it("fills templates and tells a reached route from a normal answer", () => {
    expect(fillTemplate("/api/onboarding/{id}", "..%2f")).toBe("/api/onboarding/..%2f");
    expect(fillTemplate("/t/:tenant/u/:user", "X")).toBe("/t/1/u/X");
    expect(fillTemplate("/plain", "X")).toBeUndefined();
    expect(traversalReached({ status: 504, size: 15, type: "text/plain" }, { status: 200, size: 300, type: "application/json" })).toBe(true);
    expect(traversalReached({ status: 404, size: 20, type: "text/html" }, { status: 404, size: 20, type: "text/html" })).toBe(false);
    expect(guardedRoutes(["/", "/dashboard", "/dashboard/movimientos", "/admin/users/:id", "/terms"])).toEqual(["/dashboard", "/dashboard/movimientos"]);
  });
});

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;
const ctx = (): OperationContext => ({ workspace: ws, caller: HUMAN, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner }) as unknown as OperationContext;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-webprobes-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Web", mode: "web" }, HUMAN.actor);
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/login" && url.searchParams.get("next")) return void res.writeHead(302, { location: url.searchParams.get("next")! }).end();
    if (url.pathname.startsWith("/api/onboarding/")) {
      const id = (req.url ?? "").slice("/api/onboarding/".length);
      if (/%2f|%252f|\.\.;|%5c/i.test(id)) return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ internal: true, routes: ["/health", "/users"], note: "x".repeat(200) }));
      return void res.writeHead(504, { "content-type": "text/plain" }).end("gateway timeout");
    }
    if (url.pathname.startsWith("/dashboard")) {
      if (!/session-token=/.test(req.headers.cookie ?? "")) return void res.writeHead(307, { location: "/login" }).end();
      return void res.writeHead(200, { "content-type": "text/html" }).end("<html>Panel: Movimientos</html>");
    }
    res.writeHead(404).end("no");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test", tool: "webjs" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "endpoint", key: { origin, path: "/api/onboarding/{id}" }, confidence: 1 }] } as never, HUMAN.actor);
  eng.setState("jsLeads", { [`${origin}`]: { redirectParams: ["next"], routes: ["/dashboard", "/dashboard/movimientos"] }, [origin.replace("http://127.0.0.1", "http://127.0.0.1")]: { redirectParams: ["next"], routes: ["/dashboard", "/dashboard/movimientos"] } });
});
afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("finds the open redirect, the traversal and the presence-only guard, each with its evidence", async () => {
  const redirect = (await executeOperation("web.probe_redirects", { origin, targets: [{ path: "/login", param: "next" }] }, ctx())) as { hits: string[] };
  expect(redirect.hits).toEqual(["medium: Open redirect: next on /login"]);
  const traversal = (await executeOperation("web.probe_traversal", { origin }, ctx())) as { hits: string[] };
  expect(traversal.hits[0]).toMatch(/Path parameter of \/api\/onboarding\/\{id\} walks out of its route/);
  const guard = (await executeOperation("web.probe_session_guard", { origin, paths: ["/dashboard/movimientos"] }, ctx())) as { hits: string[] };
  expect(guard.hits).toEqual(["medium: /dashboard/movimientos is served with an invented session cookie"]);
  const obs = eng.query({ kind: "observation", limit: 50 });
  expect(obs.map((o) => o.attributes.sourceRule).sort()).toEqual(["webprobe:guard", "webprobe:redirect", "webprobe:traversal"]);
  expect(obs.every((o) => o.attributes.rawId)).toBe(true);
});
