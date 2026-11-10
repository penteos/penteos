import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** Harvesting a single-page app's JavaScript: its endpoints go to the graph, its leaks to observations. */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;

const PAGE = `<!doctype html><html><head>
  <script type="module" src="/assets/app.js"></script>
</head><body><div id="root"></div></body></html>`;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-harvest-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Web", mode: "web" }, agent);
  server = createServer((req, res) => {
    if (req.url === "/assets/app.js") {
      res.writeHead(200, { "Content-Type": "application/javascript" });
      res.end(
        [
          `fetch("/api/auth/me"); axios.get("/api/tenants/public/" + slug);`,
          `const staging = "https://staging-api.corp.test/v1/internal/users";`,
          `const routes = [{ path: "/admin/documentos/:id" }];`,
          `const k = { apiKey: "AKIAIOSFODNN7EXAMPLE" };`,
        ].join("\n"),
      );
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(PAGE);
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

it("adds in-scope endpoints to the graph and records the leaks as observations", async () => {
  const r = (await executeOperation("web.harvest_scripts", { url: `${origin}/` }, ctx())) as {
    status: string;
    endpoints: string[];
    hosts: string[];
    routes: string[];
    secrets: string[];
  };
  expect(r.status).toBe("done");
  expect(r.endpoints).toContain("/api/auth/me");
  expect(r.hosts).toContain("staging-api.corp.test");
  expect(r.routes).toContain("/admin/documentos/:id");

  // In-scope endpoints are real graph entities now.
  const endpoints = eng.query({ kind: "endpoint", limit: 100 }).map((e) => String(e.attributes.pathTemplate));
  expect(endpoints).toContain("/api/auth/me");

  // The out-of-scope host, the secret and nothing else noisy became observations.
  const obs = eng.query({ kind: "observation", limit: 100 });
  expect(obs.some((o) => String(o.attributes.sourceRule) === "webjs:hosts" && String(o.attributes.detail).includes("staging-api.corp.test"))).toBe(true);
  expect(obs.some((o) => String(o.attributes.sourceRule) === "webjs:secret")).toBe(true);
});

it("refuses to harvest a page out of scope", async () => {
  await expect(executeOperation("web.harvest_scripts", { url: "https://not-in-scope.test/" }, ctx())).rejects.toMatchObject({ code: "OUT_OF_SCOPE" });
});
