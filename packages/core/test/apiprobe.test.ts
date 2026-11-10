import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** Probing endpoints for the auth boundary: the route that forgot its check is found and flagged. */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-apiprobe-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Web", mode: "web" }, agent);
  server = createServer((req, res) => {
    // Everything needs auth, except one forgotten export endpoint.
    if (req.url === "/api/reports/export") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"rows":[{"dni":"1"}]}');
      return;
    }
    if (req.url === "/api/account/forgot-password") {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end('{"message":"Cannot POST /api/account/forgot-password"}');
      return;
    }
    if (req.url?.endsWith(".css")) {
      res.writeHead(200, { "Content-Type": "text/css" });
      res.end("body{color:#000}");
      return;
    }
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end('{"error":"unauthorized"}');
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, agent);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});

afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (): OperationContext => ({
  workspace: ws,
  caller: { actor: agent, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } },
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: () => runner,
});

it("flags the endpoint that answers without auth where the rest refuse", async () => {
  const r = (await executeOperation(
    "web.probe_endpoints",
    { origin, paths: ["/api/auth/me", "/api/tenants", "/api/reports/export", "/api/users", "/api/incidents"] },
    ctx(),
  )) as { status: string; modeStatus: number; withoutAuth: string[] };
  expect(r.status).toBe("done");
  expect(r.modeStatus).toBe(401);
  expect(r.withoutAuth).toEqual(["/api/reports/export"]);

  const obs = eng.query({ kind: "observation", limit: 50 });
  expect(obs.some((o) => String(o.attributes.sourceRule) === "apiprobe:no-auth" && String(o.attributes.title).includes("/api/reports/export"))).toBe(true);
  // The endpoints are recorded with whether they require auth.
  const ep = eng.query({ kind: "endpoint", limit: 50 }).find((e) => String(e.attributes.pathTemplate) === "/api/reports/export");
  expect(ep?.attributes.statusesSeen).toContain(200);
});

it("does not flag a static asset answering without auth (public by design)", async () => {
  const r = (await executeOperation(
    "web.probe_endpoints",
    { origin, paths: ["/assets/app.css", "/api/reports/export", "/api/users", "/api/orders", "/api/me"] },
    ctx(),
  )) as { status: string; withoutAuth: string[] };
  expect(r.status).toBe("done");
  expect(r.withoutAuth).toContain("/api/reports/export");
  expect(r.withoutAuth).not.toContain("/assets/app.css");
  const obs = eng.query({ kind: "observation", limit: 50 }).map((o) => String(o.attributes.title));
  expect(obs.some((t) => t.includes("/assets/app.css"))).toBe(false);
});

it("asks for paths when the graph has none", async () => {
  const r = (await executeOperation("web.probe_endpoints", { origin }, ctx())) as { status: string; error: string };
  expect(r.status).toBe("failed");
  expect(r.error).toMatch(/no endpoints/);
});

it("approving a probe runs the whole probe, not just its first request", async () => {
  // Rate limiting is intrusive: above this agent's ceiling, so it asks.
  let hits = 0;
  server.on("request", (req) => req.url === "/api/auth/login" && hits++);
  const asked = (await executeOperation("web.probe_rate_limit", { origin, raw: "POST /api/auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"email\":\"nadie@example.com\",\"password\":\"x\"}", attempts: 6 }, ctx())) as { status: string; approvalId: string };
  expect(asked.status).toBe("pending_approval");
  expect(hits).toBe(0);
  await runner.resolveApproval(asked.approvalId, true, { type: "human", id: "01JA000000000000000000HUMN" });
  await new Promise((r) => setTimeout(r, 300));
  expect(hits).toBe(6);
  expect(eng.query({ kind: "observation", limit: 50 }).some((o) => String(o.attributes.sourceRule) === "ratelimit:none")).toBe(true);
});

it("tests several endpoints in one call and gives each a verdict", async () => {
  const human = { actor: { type: "human" as const, id: "01JA000000000000000000HUMN" }, policy: { type: "human" as const } };
  const r = (await executeOperation(
    "web.probe_rate_limit",
    { origin, raw: "POST /api/auth/login HTTP/1.1\r\n\r\n{}", more: ["POST /api/auth/forgot-password HTTP/1.1\r\n\r\n{}"], attempts: 4 },
    { ...ctx(), caller: human } as OperationContext,
  )) as { verdict: string; results: Array<{ request: string; verdict: string; attempts: number }>; note: string };
  expect(r.verdict).toBe("no_defence");
  expect(r.results.map((x) => [x.request, x.verdict, x.attempts])).toEqual([
    ["POST /api/auth/login", "no_defence", 4],
    ["POST /api/auth/forgot-password", "no_defence", 4],
  ]);
  expect(r.note).toMatch(/conclusive/);
});

it("a route that does not exist is not reported as lacking a limit", async () => {
  const human = { actor: { type: "human" as const, id: "01JA000000000000000000HUMN" }, policy: { type: "human" as const } };
  const r = (await executeOperation(
    "web.probe_rate_limit",
    { origin, raw: "POST /api/account/forgot-password HTTP/1.1\r\n\r\n{}", more: ["POST /api/auth/login HTTP/1.1\r\n\r\n{}"], attempts: 4 },
    { ...ctx(), caller: human } as OperationContext,
  )) as { verdict: string; results: Array<{ request: string; verdict: string; attempts: number }>; note: string };
  expect(r.results.map((x) => [x.request, x.verdict, x.attempts])).toEqual([
    ["POST /api/account/forgot-password", "missing", 1],
    ["POST /api/auth/login", "no_defence", 4],
  ]);
  expect(r.verdict).toBe("mixed");
  expect(r.note).toMatch(/do not exist.*forgot-password/);
  const flagged = eng.query({ kind: "observation", limit: 50 }).map((o) => String(o.attributes.title));
  expect(flagged.some((t) => t.includes("/api/account/forgot-password"))).toBe(false);
  expect(flagged.some((t) => t.includes("/api/auth/login"))).toBe(true);
});
