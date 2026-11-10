import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { canonicalOrigin, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** Mapping an app's API: origins compare in one form, and the base path of its calls is measured. */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
const servers: Server[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-apibase-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "API base", mode: "web" }, agent);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});

afterEach(async () => {
  for (const s of servers.splice(0)) await new Promise((r) => s.close(r));
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

const ROUTES = ["/clientes", "/usuarios/me", "/auth/login", "/pedidos", "/facturas"];

/** An API whose routes live under `prefix`: they ask for a session; anything else is unknown. */
async function api(prefix: string, unknown: "404" | "same200"): Promise<string> {
  const server = createServer((req, res) => {
    const path = req.url ?? "/";
    const rest = prefix && path.startsWith(`${prefix}/`) ? path.slice(prefix.length) : prefix ? null : path;
    if (rest !== null && ROUTES.includes(rest)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      return res.end('{"message":"Unauthorized"}');
    }
    if (unknown === "same200") {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end("<!doctype html><div id=root></div>");
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end('{"message":"Not Found"}');
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, agent);
  return `http://127.0.0.1:${port}`;
}

/** The calls an app's code makes, mixed with screens of its own (as a harvest leaves them). */
function rememberCalls(appOrigin: string): void {
  const screens = Array.from({ length: 60 }, (_, i) => `/admin/pantalla-${i}`);
  const calls = [...screens.slice(0, 30), ...ROUTES, ...screens.slice(30)];
  eng.setState("apiCalls", { [canonicalOrigin(appOrigin)]: calls });
}

it("origins compare in one form whatever the port notation", () => {
  expect(canonicalOrigin("https://backend3.acmecorp.test")).toBe(canonicalOrigin("https://backend3.acmecorp.test:443"));
  expect(canonicalOrigin("http://x.test")).toBe("http://x.test:80");
  expect(canonicalOrigin("https://X.test/a/b?c")).toBe("https://x.test:443");
});

for (const [prefix, unknown] of [
  ["/api", "404"],
  ["/api/v1", "404"],
  ["", "404"],
  ["/api", "same200"],
] as const) {
  it(`finds the base path of the app's calls by measuring (base "${prefix || "/"}", unknown paths answer ${unknown})`, async () => {
    const origin = await api(prefix, unknown);
    rememberCalls("http://app.lab.test");
    const r = (await executeOperation("web.probe_endpoints", { origin, fromOrigin: "http://app.lab.test" }, ctx())) as { status: string; basePath?: string };
    expect(r.status).toBe("done");
    expect(r.basePath).toBe(prefix || "/");
  });
}

it("says so when no base path has the app's calls", async () => {
  const origin = await api("/otra", "404");
  rememberCalls("http://app.lab.test");
  await expect(executeOperation("web.probe_endpoints", { origin, fromOrigin: "http://app.lab.test" }, ctx()).then((r) => r as { status: string; error?: string })).resolves.toMatchObject({ status: "failed", error: expect.stringMatching(/none of the base paths/) });
});
